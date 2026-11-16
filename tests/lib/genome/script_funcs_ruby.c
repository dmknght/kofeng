/*
 * genome / script_funcs_ruby - the Ruby function strategy (celllysis/script_funcs_ruby.c) from CONSTRUCTED text only, linked
 * against libkgenome.a alone.
 *
 * WHAT IS ASSERTED: as in script_funcs_py.c (the kit is script_funcs_kit.h): exact (off, len,
 * name_off, name_len) and END_OPEN per entry, the properties of any answer, and the same entries under CRLF and behind a BOM
 * (no lone-CR run: ruby's lexer ends a line at "\n" only, a lone CR is a blank to it).
 *
 * WHY THE OLD TESTS MISSED IT: every group is (a) - the strategy was a stub (NO_TABLE) and no Ruby function was ever read. The
 * groups that pin the keyword count (modifier if/while after a value, the "do" of a loop counted once, keywords as method names,
 * symbols and labels, "<<end" heredoc ids) are also (b): each is the boundary between two readings of the same word, which a corpus
 * of well-formed files is not chosen to hit.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

#define SF_LANG  KGENOME_TEXTUAL_LANG_RUBY
#define SF_STRAT kgenome_script_funcs_ruby
#define SF_CR    0      /* ruby's lexer: a lone CR is a blank, not a line end */

#include "script_funcs_kit.h"

/* ---- Ruby --------------------------------------------------------------------------------------------------------------- */

static void shapes(void)
{
	SF_CASE("plain", "def foo\n  1\nend\nfoo\n", { "def foo", "end", "foo", 0 });
	SF_CASE("params, at the end without a break", "x\ndef foo(a, b)\n  a\nend", { "def foo", "end", "foo", 0 });
	SF_CASE("singleton", "def self.bar\nend\n", { "def", "end", "self.bar", 0 });
	SF_CASE("receiver, one line", "def obj.baz(x) x end\n", { "def", "end", "obj.baz", 0 });
	SF_CASE("operators", "def +(o)\n  1\nend\ndef [](i)\nend\ndef <=>(o)\nend\n",
		{ "def +", "end", "+", 0 }, { "def []", "end", "[]", 0 }, { "def <=>", "end", "<=>", 0 });
	SF_CASE("singleton operator", "def self.+(o)\nend\n", { "def", "end", "self.+", 0 });
	SF_CASE("setter and predicate", "def name=(v)\n  @n = v\nend\ndef ok?\n  true\nend\n",
		{ "def name", "end", "name=", 0 }, { "def ok", "end", "ok?", 0 });
	SF_CASE("params without brackets", "def greet who, x\n  puts who\nend\n", { "def greet", "end", "greet", 0 });
	SF_CASE("visibility in front", "class A\n  private def foo\n  end\n  def bar; end\nend\n",
		{ "private", "end", "foo", 0 }, { "def bar", "end", "bar", 0 });
	SF_CASE("visibility on its own line is not the def's", "private\ndef foo\nend\n", { "def foo", "end", "foo", 0 });
}

static void endless(void)
{
	SF_CASE("endless with params", "def sq(x) = x * x\nputs 1\n", { "def sq", "x * x", "sq", 0 });
	SF_CASE("endless without params", "def one = 1\ndef two() = 2\n",
		{ "def one", "= 1", "one", 0 }, { "def two", "= 2", "two", 0 });
	SF_CASE("endless continued by an operator", "def f(a) = a +\n  1\nnext_line\n", { "def f", "  1", "f", 0 });
	SF_CASE("endless with a block", "def f = list.each do |x|\n  x\nend\ng\n", { "def f", "end", "f", 0 });
	SF_CASE("endless ended by ;", "def f = 1; def g = 2\n", { "def f", "= 1", "f", 0 }, { "def g", "= 2", "g", 0 });
	SF_CASE("endless at the end of the text", "def f = 1", { "def f", "= 1", "f", 0 });
	SF_CASE("== is not endless", "def f(a) == b\nend\n", { "def f", "end", "f", 0 });
}

static void counting(void)
{
	SF_CASE("class and module bodies: methods are units",
		"class A\n  def m\n    if x\n      1\n    end\n  end\n  def n; end\nend\nmodule M\n  def self.k\n  end\nend\n",
		{ "def m", "end\n  end", "m", 0 }, { "def n", "end", "n", 0 }, { "def self", "end", "self.k", 0 });
	SF_CASE("modifiers after a value do not open",
		"def f\n  return 1 if x\n  y unless z\n  w while v\n  q until r\n  foo(1) if a\n  ok? if b\n  done! unless c\n  yield if d\nend\nafter\n",
		{ "def f", "end", "f", 0 });
	SF_CASE("if as an expression opens", "def f\n  x = if a then 1 else 2 end\n  y = (unless b then 3 end)\nend\n",
		{ "def f", ")\nend", "f", 0 });
	SF_CASE("loop do counted once",
		"def f\n  while x do\n    y\n  end\n  for i in 1..3 do\n  end\n  until z do end\n  while (a ||\n b) do\n  end\nend\nz\n",
		{ "def f", "end\nend", "f", 0 });
	SF_CASE("blocks and braces",
		"def f\n  [1].each do |x|\n    x\n  end\n  [1].map { |y| y }\n  loop do\n    break\n  end\n  g do |a| if a then b end end\nend\n",
		{ "def f", "end\nend", "f", 0 });
	SF_CASE("begin, case, begin..end while",
		"def f\n  begin\n    1\n  rescue => e\n    2\n  ensure\n    3\n  end\n  case x\n  when 1 then 2\n  end\n  begin\n    x\n  end while y\nend\n",
		{ "def f", "end while y\nend", "f", 0 });
	SF_CASE("elsif and else if", "def f\n  if a\n    1\n  elsif b\n    2\n  else if c then 3 end\n  end\nend\n",
		{ "def f", "end\n  end\nend", "f", 0 });
	SF_CASE("one-line with ;", "def f; if a then b end; end\nx\n", { "def f", "end; end", "f", 0 });
	SF_CASE("singleton class", "class << self\n  def x\n  end\nend\n", { "def x", "end", "x", 0 });
	SF_CASE("nested def is the outer's", "def outer\n  def inner\n  end\n  inner\nend\n", { "def outer", "inner\nend", "outer", 0 });
	SF_CASE("keywords as names, symbols, labels, ivars",
		"def f\n  x.end\n  y = :end\n  z = {if: 1, end: 2, do: 3}\n  a&.class\n  @end = 1\n  $if = 2\n  e.if?\n  Foo::begin\n  alias new_end end\nend\n",
		{ "def f", "alias new_end end\nend", "f", 0 });
	SF_CASE("def named like a keyword", "def end\nend\ndef if(x) = x\n", { "def end", "end\nend", "end", 0 },
		{ "def if", "= x", "if", 0 });
	SF_CASE("variables, character literals, continued lines",
		"def f\n  @@c = 1\n  $! if x\n  c = ?d\n  if c == ?e then 1 end\n  x = 1 + \\\n  2 if y\nend\n", { "def f", "y\nend", "f", 0 });
	SF_CASE("data after __END__", "def f\nend\n__END__\ndef g\n", { "def f", "end", "f", 0 });
}

static void literals(void)
{
	SF_NONE("strings, %-literals, regex, heredoc, comments",
		"s = 'def no; end'\nt = \"def x\nend\"\nu = %w[def end if]\nr = /def end/\nh = <<~EOS\n  def hidden\n  end\nEOS\n"
		"# def c\n=begin\ndef d\n=end\nq = \"#{if x then 1 end}\"\n");
	SF_CASE("heredoc ids that are keywords", "def f\n  a = <<end\nx\nend\n  b = <<-if\n  y\n  if\nend\n",
		{ "def f", "if\nend", "f", 0 });
	SF_CASE("a keyword in a string inside a def", "def f\n  puts 'end'\n  puts \"if\"\nend\n", { "def f", "\"if\"\nend", "f", 0 });
}

static void open_ends(void)
{
	SF_CASE("unterminated in a class", "class A\n  def m\n    if x\n", { "def m", NULL, "m", 1 });
	SF_CASE("header not closed", "def f(a,\n", { "def f", NULL, "f", 1 });
	SF_CASE("endless with an open block", "def f = g do\n", { "def f", NULL, "f", 1 });
	SF_CASE("one closed, one open", "def a\nend\ndef b\n  while x do\n", { "def a", "end", "a", 0 }, { "def b", NULL, "b", 1 });
}

static void hostile(void)
{
	sf_hostile("100000 one-line defs", "", "def f; end\n", 100000u, 100000u);
	sf_hostile("100000 nested if in one def", "def f\n", "if x\n", 100000u, 1u);
	sf_hostile("100000 nested defs", "", "def f\n", 100000u, 1u);
	sf_hostile("100000 stray end", "", "end\n", 100000u, 0u);
	sf_hostile("100000 headers with an open bracket", "", "def f(\n", 100000u, 1u);
	sf_hostile("100000 endless defs", "", "def f(x) = x\n", 100000u, 100000u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	endless();
	counting();
	literals();
	open_ends();
	hostile();
	if (hk_fails) {
		printf("script_funcs_ruby: %d FAILED\n", hk_fails);
		return 1;
	}
	printf("script_funcs_ruby: ok\n");
	return 0;
}
