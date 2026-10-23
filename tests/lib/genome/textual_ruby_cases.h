#ifndef KGENOME_TEST_TEXTUAL_RUBY_CASES_H
#define KGENOME_TEST_TEXTUAL_RUBY_CASES_H

/*
 * textual_ruby_cases.h - the known answers of textual_ruby.c, one construct and the neighbour it could be confused for per
 * case, in the order of the language's own rules. Included by textual_ruby.c only, after rb() and rbx().
 *
 * rb(...) is a case ruby 3.3.8's own lexer agrees with: a scratch script outside the tree wrote every rb() text to a file,
 * read its string and comment tokens with `Ripper` and compared them with the lexer's, span for span (the heredoc "operator"
 * and a symbol's ":" are code in the lexer's model, a body runs through its closing line without the break, a pattern has its
 * options). rbx(...) is a case the interpreter cannot confirm and says why in the group's comment: text that is not a program
 * (not closed; ripper reports the error and has no end to give), a name the interpreter knows is a local variable (here it is
 * ARG, and the decision is the method reading), or a line the lexer reads where the interpreter refuses it (an indented
 * "=begin" or "__END__": see ruby_lex.c).
 * Flags: S* = escapes the form may write, S! = not closed, S# = a heredoc body (see textual_check.h).
 */

static void cases(void)
{
	/* comments */
	rb("# c\nx", "K{# c}C{\nx}");
	rb("x = 1 # c\ny", "C{x = 1 }K{# c}C{\ny}");
	rb("# c\r\nx", "K{# c}C{\r\nx}");
	rb("# a # b\n", "K{# a # b}C{\n}");
	rb("#!/usr/bin/env ruby -w\nx = 1", "K{#!/usr/bin/env ruby -w}C{\nx = 1}");
	rb("# \"q' \\\ny", "K{# \"q' \\}C{\ny}");
	rb("x = \"#\" # \"", "C{x = }S*{\"#\"}C{ }K{# \"}");
	rb("\"a\" # #{b}", "S*{\"a\"}C{ }K{# #{b}}");
	rb("x = 1 #", "C{x = 1 }K{#}");
	rb("\xef\xbb\xbf# c\nx", "C{\xef\xbb\xbf}K{# c}C{\nx}");
	rb("a = [1, # c\n 2, # d\n]", "C{a = [1, }K{# c}C{\n 2, }K{# d}C{\n]}");
	rb("x = ?# # c\ny", "C{x = ?# }K{# c}C{\ny}");
	rb("x = ?\\# # c", "C{x = ?\\# }K{# c}");
	rb("puts 1 # c \\\nputs 2", "C{puts 1 }K{# c \\}C{\nputs 2}");
	rb("# c\n\n# d\nx", "K{# c}C{\n\n}K{# d}C{\nx}");
	/* block comments */
	rb("=begin\nx \"y\n=end\nz", "K{=begin\nx \"y\n=end}C{\nz}");
	rb("=begin t\n=end t\nz", "K{=begin t\n=end t}C{\nz}");
	rb("=begin\n=end", "K{=begin\n=end}");
	rb("x\n=begin\n=end\ny", "C{x\n}K{=begin\n=end}C{\ny}");
	rb("x = 1\n=begin\r\ncom\r\n=end\r\ny = 2", "C{x = 1\n}K{=begin\r\ncom\r\n=end}C{\r\ny = 2}");
	rb("\"a\n=begin\nb\"", "S*{\"a\n=begin\nb\"}");
	rb("=begin\n=begin\n=end\n=end\nz", "K{=begin\n=begin\n=end}C{\n=end\nz}");
	rb("x\n=end\ny", "C{x\n=end\ny}");
	rb("=begin\n=endx\n=end\nz", "K{=begin\n=endx\n=end}C{\nz}");
	rb("=begin\n=end foo bar\nz", "K{=begin\n=end foo bar}C{\nz}");
	rb("=begin\n#{ \" \n=end\nx = 'y'", "K{=begin\n#{ \" \n=end}C{\nx = }S{'y'}");
	rb("x = <<A\n=begin\nA\n=end\ny", "C{x = <<A\n}S*#{=begin\nA}C{\n=end\ny}");
	/* not confirmed: no program: an unclosed block comment, an indented marker (the lexer reads it, the interpreter refuses it) */
	rbx("=begin\nabc", "K!{=begin\nabc}");
	rbx("=begin", "K!{=begin}");
	rbx("x\n  =begin\ny = \"a\"\n  =end\nz = \"b\"", "C{x\n  }K!{=begin\ny = \"a\"\n  =end\nz = \"b\"}");
	rbx("\t=begin\n=end\n", "C{\t}K{=begin\n=end}C{\n}");
	rbx("=begin\n  =end\nstill\n=end\nafter", "K{=begin\n  =end\nstill\n=end}C{\nafter}");
	rbx("=begin# c\nx\n=end\ny", "K{=begin# c\nx\n=end}C{\ny}");
	rbx("=begin #c\n=end", "K{=begin #c\n=end}");
	/* __END__ */
	rb("x = 1\n__END__\ndata \"x\n#{", "C{x = 1\n}S{__END__\ndata \"x\n#{}");
	rb("x = 1\n__END__", "C{x = 1\n}S{__END__}");
	rb("x = 1\n__END__\n", "C{x = 1\n}S{__END__\n}");
	rb("__END__\nabc", "S{__END__\nabc}");
	rb("x\n__END__x\ny", "C{x\n__END__x\ny}");
	rb("x__END__\ny", "C{x__END__\ny}");
	rb("puts \"__END__\"\n__END__\nz", "C{puts }S*{\"__END__\"}C{\n}S{__END__\nz}");
	rb("x = <<A\n__END__\nA\ny = \"s\"", "C{x = <<A\n}S*#{__END__\nA}C{\ny = }S*{\"s\"}");
	rb("x = 1\n__END__\r\nd\r\n", "C{x = 1\n}S{__END__\r\nd\r\n}");
	rb("# c\n__END__\n=begin\n\"", "K{# c}C{\n}S{__END__\n=begin\n\"}");
	/* not confirmed: an indented marker, one with blanks or a comment after it, is read (see ruby_lex.c) */
	rbx("x = 1\n  __END__\ny", "C{x = 1\n  }S{__END__\ny}");
	rbx("\t__END__\n\"data", "C{\t}S{__END__\n\"data}");
	rbx("x\n__END__ \ny", "C{x\n}S{__END__ \ny}");
	rbx("x\n__END__  # c\ndata \"x", "C{x\n}S{__END__  # c\ndata \"x}");
	rbx("x\n__END__#c\r\nd", "C{x\n}S{__END__#c\r\nd}");
	/* single quotes */
	rb("'a\\'b'", "S{'a\\'b'}");
	rb("'a\\\\'", "S{'a\\\\'}");
	rb("'\\n'", "S{'\\n'}");
	rb("'a' 'b'", "S{'a'}C{ }S{'b'}");
	rb("'a\nb'", "S{'a\nb'}");
	rb("x = 'it''s'", "C{x = }S{'it'}S{'s'}");
	rb("puts 'a#{b}'", "C{puts }S{'a#{b}'}");
	rb("'\"' + '`'", "S{'\"'}C{ + }S{'`'}");
	rb("''", "S{''}");
	rb("x='a'+'b'", "C{x=}S{'a'}C{+}S{'b'}");
	/* double quotes */
	rb("\"a\\\"b\"", "S*{\"a\\\"b\"}");
	rb("\"a\\\\\"", "S*{\"a\\\\\"}");
	rb("\"a\nb\"", "S*{\"a\nb\"}");
	rb("\"\" \"\"", "S*{\"\"}C{ }S*{\"\"}");
	rb("x = \"a\" \"b\"", "C{x = }S*{\"a\"}C{ }S*{\"b\"}");
	rb("\"'\" + \"`\"", "S*{\"'\"}C{ + }S*{\"`\"}");
	rb("`ls`", "S*{`ls`}");
	rb("`a\\`b`", "S*{`a\\`b`}");
	rb("\"a\\n\\x41\\101\\u0041\\u{41}\\M-a\\C-a\\cA\"", "S*{\"a\\n\\x41\\101\\u0041\\u{41}\\M-a\\C-a\\cA\"}");
	rb("x = \"\\#{a}\"", "C{x = }S*{\"\\#{a}\"}");
	rb("\"a\\\r\nb\"", "S*{\"a\\\r\nb\"}");
	rb("\"%d\" % 3", "S*{\"%d\"}C{ % 3}");
	/* quotes */
	/* not confirmed: no program: not closed */
	rbx("\"abc", "S*!{\"abc}");
	rbx("'abc", "S!{'abc}");
	rbx("`abc", "S*!{`abc}");
	rbx("x = 'a\\", "C{x = }S!{'a\\}");
	rbx("\"a\\", "S*!{\"a\\}");
	/* percent literals */
	rb("%q(a (b) c) %Q[a [x] #{1}] %w[a b] %W(a#{x} b)", "S{%q(a (b) c)}C{ %Q[a [x] }K{#{1}] %w[a b] %W(a#{x} b)}");
	rb("%i[a b] %I[a#{x}] %r{a/b}i %s(sym) %x(ls) %(bare (nested))", "S{%i[a b]}C{ %I[a}K{#{x}] %r{a/b}i %s(sym) %x(ls) %(bare (nested))}");
	rb("%q()", "S{%q()}");
	rb("%w[]", "S{%w[]}");
	rb("%()", "S*{%()}");
	rb("%Q<a<b>c>", "S*{%Q<a<b>c>}");
	rb("%q{a{b}c}", "S{%q{a{b}c}}");
	rb("%q|a|", "S{%q|a|}");
	rb("%q!a!", "S{%q!a!}");
	rb("%q-a-", "S{%q-a-}");
	rb("%q#a#", "S{%q#a#}");
	rb("%Q'a'", "S*{%Q'a'}");
	rb("%Q\"a\"", "S*{%Q\"a\"}");
	rb("%q(a\\)b)", "S{%q(a\\)b)}");
	rb("%q|a\\|b|", "S{%q|a\\|b|}");
	rb("%q(a\\\\)", "S{%q(a\\\\)}");
	rb("%w[a\\ b c\\]d]", "S{%w[a\\ b c\\]d]}");
	rb("%q(a\nb)", "S{%q(a\nb)}");
	rb("%r!a!x", "S{%r!a!x}");
	rb("%r<a<b>>mi", "S{%r<a<b>>mi}");
	rb("%Q(a #{b} (c) #{d(\")\")})", "S{%Q(a #{b} (c) #{d(\")\")})}");
	rb("%W[a#{ \"]\" } b]", "S{%W[a#{ \"]\" } b]}");
	rb("%q(a #{b})", "S{%q(a #{b})}");
	rb("%s(a b)", "S{%s(a b)}");
	rb("x = %w[a b].map { |s| s + \"1\" }", "C{x = }S{%w[a b]}C{.map { |s| s + }S*{\"1\"}C{ }}");
	rb("foo(%w[a], %i[b])", "C{foo(}S{%w[a]}C{, }S{%i[b]}C{)}");
	rb("puts %w[a b]", "C{puts }S{%w[a b]}");
	rb("x = [%w[a], %q(b)]", "C{x = [}S{%w[a]}C{, }S{%q(b)}C{]}");
	rb("x = y ? %q(a) : %q(b)", "C{x = y ? }S{%q(a)}C{ : }S{%q(b)}");
	rb("%w[a\nb\nc]", "S{%w[a\nb\nc]}");
	rb("%w(\n  a\n  b\n)", "S{%w(\n  a\n  b\n)}");
	/* percent or modulo */
	rb("x = 7 % 3", "C{x = 7 % 3}");
	rb("x = a % b", "C{x = a % b}");
	rb("x = a%b", "C{x = a%b}");
	rb("y = (a) % b", "C{y = (a) % b}");
	rb("z = a[0] % 2", "C{z = a[0] % 2}");
	rb("s = \"%d\" % 3", "C{s = }S*{\"%d\"}C{ % 3}");
	rb("t = '%s' % x", "C{t = }S{'%s'}C{ % x}");
	rb("u = x.y % z", "C{u = x.y % z}");
	rb("x = 5\ny = x % 2\nz = x%2", "C{x = 5\ny = x % 2\nz = x%2}");
	rb("x = 5 % 3 + %w[a].size", "C{x = 5 % 3 + }S{%w[a]}C{.size}");
	rb("puts %w[a]\nputs %(a)", "C{puts }S{%w[a]}C{\nputs }S*{%(a)}");
	rb("puts(%w[a])", "C{puts(}S{%w[a]}C{)}");
	rb("return %w[a]", "C{return }S{%w[a]}");
	rb("x = [1, %w[a]]", "C{x = [1, }S{%w[a]}C{]}");
	rb("x %= 3", "C{x %= 3}");
	rb("x = y %= 2", "C{x = y %= 2}");
	rb("a = 1 if b % 2 == 0", "C{a = 1 if b % 2 == 0}");
	rb("if x then %w[a] end", "C{if x then }S{%w[a]}C{ end}");
	rb("x = *%w[a]", "C{x = *}S{%w[a]}");
	rb("x = {a: %w[b]}", "C{x = {a: }S{%w[b]}C{}}");
	rb("x = b ? 1 : %w[a]", "C{x = b ? 1 : }S{%w[a]}");
	/* not confirmed: the interpreter knows x is a variable (a name is not tracked here, ARG) */
	rbx("x = 5\ny = x %2", "C{x = 5\ny = x %2}");
	rbx("x = 5\ny = x %(2)", "C{x = 5\ny = x }S*{%(2)}");
	rbx("x = 5\ny = x %w[a]", "C{x = 5\ny = x }S{%w[a]}");
	/* regular expressions */
	rb("/a/", "S{/a/}");
	rb("/a\\/b/i", "S{/a\\/b/i}");
	rb("/#{x}/mx", "S{/#{x}/mx}");
	rb("x = /[a-z]+/ui", "C{x = }S{/[a-z]+/ui}");
	rb("puts /a/", "C{puts }S{/a/}");
	rb("puts(/a/)", "C{puts(}S{/a/}C{)}");
	rb("[/a/, /b/]", "C{[}S{/a/}C{, }S{/b/}C{]}");
	rb("a =~ /b/", "C{a =~ }S{/b/}");
	rb("a !~ /b/", "C{a !~ }S{/b/}");
	rb("case x\nwhen /a/ then 1\nend", "C{case x\nwhen }S{/a/}C{ then 1\nend}");
	rb("x = y / 2", "C{x = y / 2}");
	rb("x = y/2/3", "C{x = y/2/3}");
	rb("x = y / 2 / 3", "C{x = y / 2 / 3}");
	rb("x = a.b / c.d / 2", "C{x = a.b / c.d / 2}");
	rb("1 / 2 / 3", "C{1 / 2 / 3}");
	rb("x = (a) / 2", "C{x = (a) / 2}");
	rb("x = a[0] / 2", "C{x = a[0] / 2}");
	rb("x = 5 / 2 + /a/.source.size", "C{x = 5 / 2 + }S{/a/}C{.source.size}");
	rb("if /a/ then 1 end", "C{if }S{/a/}C{ then 1 end}");
	rb("return /a/ if x", "C{return }S{/a/}C{ if x}");
	rb("foo(/a/, /b/)", "C{foo(}S{/a/}C{, }S{/b/}C{)}");
	rb("x.gsub /a/, 'b'", "C{x.gsub }S{/a/}C{, }S{'b'}");
	rb("x.gsub(/\\//, '/')", "C{x.gsub(}S{/\\//}C{, }S{'/'}C{)}");
	rb("x = y if /a/ =~ z", "C{x = y if }S{/a/}C{ =~ z}");
	rb("while x do /a/ end", "C{while x do }S{/a/}C{ end}");
	rb("%r{a}", "S{%r{a}}");
	rb("x = /a/imxounse", "C{x = }S{/a/imxounse}");
	rb("/a\nb/", "S{/a\nb/}");
	rb("/a#{b}c#{d}/", "S{/a#{b}c#{d}/}");
	rb("/#{\"/\"}/", "S{/#{\"/\"}/}");
	rb("x = [1, /a/ =~ y]", "C{x = [1, }S{/a/}C{ =~ y]}");
	rb("puts a ? /x/ : /y/", "C{puts a ? }S{/x/}C{ : }S{/y/}");
	rb("a && /b/", "C{a && }S{/b/}");
	rb("when_x = x == /a/", "C{when_x = x == }S{/a/}");
	rb("x = (y) /2/ 3", "C{x = (y) /2/ 3}");
	rb("{a: /x/}", "C{{a: }S{/x/}C{}}");
	rb("x ? /a/ : /b/", "C{x ? }S{/a/}C{ : }S{/b/}");
	rb("not /a/", "C{not }S{/a/}");
	rb("x = y.map { |z| z / 2 }", "C{x = y.map { |z| z / 2 }}");
	rb("x = a.b /c.d/ 2", "C{x = a.b }S{/c.d/}C{ 2}");
	/* not confirmed: no program: not closed, or a class that holds the delimiter */
	rbx("x = /abc", "C{x = }S!{/abc}");
	rbx("/a/z", "S{/a/z}");
	rbx("x = /a#{b", "C{x = }S!{/a#{b}");
	rbx("x = /[/]/\ny = 1", "C{x = }S{/[/}C{]/\ny = 1}");
	/* not confirmed: the interpreter knows x is a variable */
	rbx("x = 4\ny = x /2\nz = 1", "C{x = 4\ny = x }S!{/2\nz = 1}");
	rbx("x = 4\ny = x /2/ 3", "C{x = 4\ny = x }S{/2/}C{ 3}");
	/* character literals */
	rb("?a", "C{?a}");
	rb("x = ?a + ?b", "C{x = ?a + ?b}");
	rb("[?a, ?b, ?\\n]", "C{[?a, ?b, ?\\n]}");
	rb("?\\C-a", "C{?\\C-a}");
	rb("?\\M-\\C-a", "C{?\\M-\\C-a}");
	rb("?\\u0041", "C{?\\u0041}");
	rb("?\\u{41}", "C{?\\u{41}}");
	rb("?\\x41", "C{?\\x41}");
	rb("?\\101", "C{?\\101}");
	rb("?\\\\", "C{?\\\\}");
	rb("x = ?\"", "C{x = ?\"}");
	rb("x = ?'", "C{x = ?'}");
	rb("x = ?`", "C{x = ?`}");
	rb("x = ?%", "C{x = ?%}");
	rb("x = ?/", "C{x = ?/}");
	rb("x = ?(", "C{x = ?(}");
	rb("x = ?\\s", "C{x = ?\\s}");
	rb("x = ?\xc3\xa9 + 1", "C{x = ?\xc3\xa9 + 1}");
	rb("puts ?a", "C{puts ?a}");
	rb("x = [?[, ?]]", "C{x = [?[, ?]]}");
	rb("y = ?{ + ?}", "C{y = ?{ + ?}}");
	/* ternary */
	rb("x = a ? b : c", "C{x = a ? b : c}");
	rb("x = a ? \"b\" : 'c'", "C{x = a ? }S*{\"b\"}C{ : }S{'c'}");
	rb("x = a.empty? ? 1 : 2", "C{x = a.empty? ? 1 : 2}");
	rb("x = a.b? ? 1 : 2", "C{x = a.b? ? 1 : 2}");
	rb("x = a ?b : c", "C{x = a ?b : c}");
	rb("x = y ?1 : 2", "C{x = y ?1 : 2}");
	rb("x = 1 ? 2 : 3", "C{x = 1 ? 2 : 3}");
	rb("x = (a) ? 1 : 2", "C{x = (a) ? 1 : 2}");
	rb("x = a ? b ? 1 : 2 : 3", "C{x = a ? b ? 1 : 2 : 3}");
	rb("x = a ? :b : :c", "C{x = a ? :b : :c}");
	rb("x = a ? %w[b] : %w[c]", "C{x = a ? }S{%w[b]}C{ : }S{%w[c]}");
	rb("x = a ?\n b :\n c", "C{x = a ?\n b :\n c}");
	rb("x = a == b ? /c/ : /d/", "C{x = a == b ? }S{/c/}C{ : }S{/d/}");
	rb("puts x ? 'a' : 'b'", "C{puts x ? }S{'a'}C{ : }S{'b'}");
	rb("x = a ? [1, 2] : {a: 1}", "C{x = a ? [1, 2] : {a: 1}}");
	rb("puts(a ? 1 : 2, ?b)", "C{puts(a ? 1 : 2, ?b)}");
	rb("x = defined?(a) ? 1 : 2", "C{x = defined?(a) ? 1 : 2}");
	rb("x = !a ? 1 : 2", "C{x = !a ? 1 : 2}");
	/* not confirmed: the interpreter knows what the name is */
	rbx("x = y ?a : b", "C{x = y ?a : b}");
	/* symbols */
	rb("x = :foo", "C{x = :foo}");
	rb("x = :\"bar baz\"", "C{x = :}S*{\"bar baz\"}");
	rb("x = :'x y'", "C{x = :}S{'x y'}");
	rb("x = :\"a#{b}c\"", "C{x = :}S{\"a#{b}c\"}");
	rb("x = :foo?", "C{x = :foo?}");
	rb("x = :foo!", "C{x = :foo!}");
	rb("x = :foo=", "C{x = :foo=}");
	rb("x = :Foo", "C{x = :Foo}");
	rb("x = :@a", "C{x = :@a}");
	rb("x = :$a", "C{x = :$a}");
	rb("x = :@@a", "C{x = :@@a}");
	rb("x = :+", "C{x = :+}");
	rb("x = :[]=", "C{x = :[]=}");
	rb("x = :[]", "C{x = :[]}");
	rb("x = :<=>", "C{x = :<=>}");
	rb("x = :==", "C{x = :==}");
	rb("x = :!", "C{x = :!}");
	rb("x = :-@", "C{x = :-@}");
	rb("x = :**", "C{x = :**}");
	rb("x = :<<", "C{x = :<<}");
	rb("x = :/", "C{x = :/}");
	rb("x = :%", "C{x = :%}");
	rb("x = :`", "C{x = :`}");
	rb("[1].inject(:/)", "C{[1].inject(:/)}");
	rb("[1].inject(:%)", "C{[1].inject(:%)}");
	rb("x.send(:<<, 1)", "C{x.send(:<<, 1)}");
	rb("x.map(&:/)", "C{x.map(&:/)}");
	rb("x.map(&:to_s)", "C{x.map(&:to_s)}");
	rb("x = {a: 1}", "C{x = {a: 1}}");
	rb("x = {\"a\": 1}", "C{x = {}S*{\"a\"}C{: 1}}");
	rb("x = {'a': 1}", "C{x = {}S{'a'}C{: 1}}");
	rb("x = {\"a#{b}\": 1}", "C{x = {}S{\"a#{b}\"}C{: 1}}");
	rb("x = {:a => 1, :\"b\" => 2}", "C{x = {:a => 1, :}S*{\"b\"}C{ => 2}}");
	rb("x = a ? b : \"c\"", "C{x = a ? b : }S*{\"c\"}");
	rb("x = a ? b :\"c\"", "C{x = a ? b :}S*{\"c\"}");
	rb("puts :\"x y\"", "C{puts :}S*{\"x y\"}");
	rb("foo(:a, :\"b c\")", "C{foo(:a, :}S*{\"b c\"}C{)}");
	rb("x = {a: :b, c: :\"d\"}", "C{x = {a: :b, c: :}S*{\"d\"}C{}}");
	rb("x = a ? :b : :\"c\"", "C{x = a ? :b : :}S*{\"c\"}");
	rb("x = a ? 1 : :b", "C{x = a ? 1 : :b}");
	rb("obj&.m :s", "C{obj&.m :s}");
	rb("p(a ?:b : :c)", "C{p(a ?:b : :c)}");
	rb("x = [:a, :b, :\"c\"]", "C{x = [:a, :b, :}S*{\"c\"}C{]}");
	rb("alias :a :b", "C{alias :a :b}");
	rb("x = y ? \"a\":\"b\"", "C{x = y ? }S*{\"a\"}C{:}S*{\"b\"}");
	rb("x = {if: 1, class: \"a\", end: 'b'}", "C{x = {if: 1, class: }S*{\"a\"}C{, end: }S{'b'}C{}}");
	rb("puts a: \"x\", b: 'y'", "C{puts a: }S*{\"x\"}C{, b: }S{'y'}");
	/* global variables */
	rb("$'", "C{$'}");
	rb("$\"", "C{$\"}");
	rb("$`", "C{$`}");
	rb("$/", "C{$/}");
	rb("$,", "C{$,}");
	rb("$;", "C{$;}");
	rb("$.", "C{$.}");
	rb("$:", "C{$:}");
	rb("$<", "C{$<}");
	rb("$>", "C{$>}");
	rb("$!", "C{$!}");
	rb("$@", "C{$@}");
	rb("$&", "C{$&}");
	rb("$~", "C{$~}");
	rb("$*", "C{$*}");
	rb("$$", "C{$$}");
	rb("$?", "C{$?}");
	rb("$\\", "C{$\\}");
	rb("$0", "C{$0}");
	rb("$1", "C{$1}");
	rb("$12", "C{$12}");
	rb("$-w", "C{$-w}");
	rb("$_", "C{$_}");
	rb("$stdout", "C{$stdout}");
	rb("x = $' + \"a\"", "C{x = $' + }S*{\"a\"}");
	rb("x = $\" + 'a'", "C{x = $\" + }S{'a'}");
	rb("puts $', $\"", "C{puts $', $\"}");
	rb("x = $` + '#'", "C{x = $` + }S{'#'}");
	rb("x = $/ # c", "C{x = $/ }K{# c}");
	rb("x = $, # \"", "C{x = $, }K{# \"}");
	rb("if $' then \"a\" end", "C{if $' then }S*{\"a\"}C{ end}");
	rb("x = $; + $, + 'a'", "C{x = $; + $, + }S{'a'}");
	rb("$stderr.puts $'", "C{$stderr.puts $'}");
	rb("x = [$', \"a\", $\", 'b']", "C{x = [$', }S*{\"a\"}C{, $\", }S{'b'}C{]}");
	rb("x = \"#$' b\"", "C{x = }S{\"#$' b\"}");
	rb("x = \"#$\" c\"", "C{x = }S{\"#$\" c\"}");
	rb("x = \"#$1 #$-w #$stdout #@a #@@b\"", "C{x = }S{\"#$1 #$-w #$stdout #@a #@@b\"}");
	rb("x = \"#@ #$ # \"", "C{x = }S*{\"#@ #$ # \"}");
	/* not confirmed: no program: the quote is the variable's, so the string is not closed (ripper reports the error and has no end) */
	rbx("x = \"#$\"\ny = 1", "C{x = }S!{\"#$\"\ny = 1}");
	/* interpolation */
	rb("x = \"a#{b}c\"", "C{x = }S{\"a#{b}c\"}");
	rb("x = \"a#{ \"b#{ \"c\" } d\" }e\" + \"f#{ {a: 1}[:a] }g\"", "C{x = }S{\"a#{ \"b#{ \"c\" } d\" }e\"}C{ + }S{\"f#{ {a: 1}[:a] }g\"}");
	rb("\"a#{x # comment }\n}b\"", "S{\"a#{x # comment }\n}b\"}");
	rb("x = \"#{%w[a} b]}\"", "C{x = }S{\"#{%w[a} b]}\"}");
	rb("x = \"#{'}'}\"", "C{x = }S{\"#{'}'}\"}");
	rb("x = \"#{\"}\"}\"", "C{x = }S{\"#{\"}\"}\"}");
	rb("x = \"#{x =~ /}/}\"", "C{x = }S{\"#{x =~ /}/}\"}");
	rb("x = \"#{ x.map { |y| \"#{y}\" }.join }\"", "C{x = }S{\"#{ x.map { |y| \"#{y}\" }.join }\"}");
	rb("x = \"#{}\"", "C{x = }S{\"#{}\"}");
	rb("x = \"#{ }\"", "C{x = }S{\"#{ }\"}");
	rb("\"#\"", "S*{\"#\"}");
	rb("\"#a\"", "S*{\"#a\"}");
	rb("\"\\#{a}\"", "S*{\"\\#{a}\"}");
	rb("'#{a}'", "S{'#{a}'}");
	rb("\"#@a#@b #@@c\"", "S{\"#@a#@b #@@c\"}");
	rb("\"##{a}\"", "S{\"##{a}\"}");
	rb("\"#{a}#{b}\"", "S{\"#{a}#{b}\"}");
	rb("\"#{ \"a\" } #{ 'b' } #{ `c` } #{ %w[d] }\"", "S{\"#{ \"a\" } #{ 'b' } #{ `c` } #{ %w[d] }\"}");
	rb("x = \"a#{\n  b\n}c\"", "C{x = }S{\"a#{\n  b\n}c\"}");
	rb("x = \"a#{b ? \"c\" : 'd'}e\"", "C{x = }S{\"a#{b ? \"c\" : 'd'}e\"}");
	rb("`a#{b}c`", "S{`a#{b}c`}");
	rb("%Q(a#{b}c)", "S{%Q(a#{b}c)}");
	rb("%(a#{b}c)", "S{%(a#{b}c)}");
	rb("/a#{b}c/", "S{/a#{b}c/}");
	rb(":\"a#{b}c\"", "C{:}S{\"a#{b}c\"}");
	rb("%W[#{a} #{b}]", "S{%W[#{a} #{b}]}");
	rb("x = \"a#{ <<A }b\"\nbody\nA\ny = 1", "C{x = }S{\"a#{ <<A }b\"}C{\n}S*#{body\nA}C{\ny = 1}");
	rb("x = \"#{\"#{\"#{\"#{\"x\"}\"}\"}\"}\"", "C{x = }S{\"#{\"#{\"#{\"#{\"x\"}\"}\"}\"}\"}");
	rb("\"a#{b}\" + \"c#{d}\"", "S{\"a#{b}\"}C{ + }S{\"c#{d}\"}");
	/* not confirmed: no program: not closed */
	rbx("x = \"a#{b", "C{x = }S!{\"a#{b}");
	rbx("x = \"a#{\"b\"", "C{x = }S!{\"a#{\"b\"}");
	rbx("x = \"a#{b}", "C{x = }S!{\"a#{b}}");
	rbx("x = \"#{ # }\"", "C{x = }S!{\"#{ # }\"}");
	/* heredocs */
	rb("x = <<A\nbody #{y}\nA\nz = 1", "C{x = <<A\n}S#{body #{y}\nA}C{\nz = 1}");
	rb("x = <<-A\n  body\n  A\nz = 1", "C{x = <<-A\n}S*#{  body\n  A}C{\nz = 1}");
	rb("x = <<~A\n  body\n  A\nz = 1", "C{x = <<~A\n}S*#{  body\n  A}C{\nz = 1}");
	rb("x = <<\"A\"\nb #{y}\nA\nz", "C{x = <<\"A\"\n}S#{b #{y}\nA}C{\nz}");
	rb("x = <<'A'\nb #{y} \\n\nA\nz", "C{x = <<'A'\n}S#{b #{y} \\n\nA}C{\nz}");
	rb("x = <<`A`\nls\nA\nz", "C{x = <<`A`\n}S*#{ls\nA}C{\nz}");
	rb("x = <<-'A'\n  b\n  A\nz", "C{x = <<-'A'\n}S#{  b\n  A}C{\nz}");
	rb("x = <<~\"A B\"\n  b\nA B\nz", "C{x = <<~\"A B\"\n}S*#{  b\nA B}C{\nz}");
	rb("foo(<<A, <<B)\nbody a\nA\nbody b\nB\nbar", "C{foo(<<A, <<B)\n}S*#{body a\nA}C{\n}S*#{body b\nB}C{\nbar}");
	rb("foo(<<A, <<'B', <<~C)\na\nA\nb\nB\n c\nC\nbar", "C{foo(<<A, <<'B', <<~C)\n}S*#{a\nA}C{\n}S#{b\nB}C{\n}S*#{ c\nC}C{\nbar}");
	rb("x = <<A.strip + \"z\"\n  body\nA\ny = 1", "C{x = <<A.strip + }S*{\"z\"}C{\n}S*#{  body\nA}C{\ny = 1}");
	rb("x = [<<A, <<B]\n1\nA\n2\nB\n", "C{x = [<<A, <<B]\n}S*#{1\nA}C{\n}S*#{2\nB}C{\n}");
	rb("x = <<A # comment \"\nbody\nA\ny", "C{x = <<A }K{# comment \"}C{\n}S*#{body\nA}C{\ny}");
	rb("x = <<A + 'c' + <<B\n1\nA\n2\nB\n", "C{x = <<A + }S{'c'}C{ + <<B\n}S*#{1\nA}C{\n}S*#{2\nB}C{\n}");
	rb("puts(<<A.upcase, 1)\nbody\nA\n", "C{puts(<<A.upcase, 1)\n}S*#{body\nA}C{\n}");
	rb("x = <<A\nA\ny = \"s\"", "C{x = <<A\n}S*#{A}C{\ny = }S*{\"s\"}");
	rb("x = <<A\n\nA\ny", "C{x = <<A\n}S*#{\nA}C{\ny}");
	rb("x = <<A\n  A\nA\ny = 'q'", "C{x = <<A\n}S*#{  A\nA}C{\ny = }S{'q'}");
	rb("x = <<-A\n  A\ny = 'q'\n", "C{x = <<-A\n}S*#{  A}C{\ny = }S{'q'}C{\n}");
	rb("x = <<A\nA \nA\ny", "C{x = <<A\n}S*#{A \nA}C{\ny}");
	rb("x = <<A\r\nb\r\nA\r\ny = 'q'\r\n", "C{x = <<A\r\n}S*#{b\r\nA}C{\r\ny = }S{'q'}C{\r\n}");
	rb("x = <<A\nfoo \\\nA\nstill\nA\ny = 'q'", "C{x = <<A\n}S*#{foo \\\nA\nstill\nA}C{\ny = }S{'q'}");
	rb("x = <<'A'\nfoo \\\nA\nz = 'q'", "C{x = <<'A'\n}S#{foo \\\nA}C{\nz = }S{'q'}");
	rb("x = <<~A\n  #{ y.map { |z|\n  \"#{z}\"\n } } w\nA\nz = 'q'", "C{x = <<~A\n}S#{  #{ y.map { |z|\n  \"#{z}\"\n } } w\nA}C{\nz = }S{'q'}");
	rb("x = \"#{<<A}\"\nbody\nA\ny = 1", "C{x = }S{\"#{<<A}\"}C{\n}S*#{body\nA}C{\ny = 1}");
	rb("x = <<A\nb\nA\nputs <<B\nc\nB\n", "C{x = <<A\n}S*#{b\nA}C{\nputs <<B\n}S*#{c\nB}C{\n}");
	rb("if x\n  puts <<A\n  t\nA\nend", "C{if x\n  puts <<A\n}S*#{  t\nA}C{\nend}");
	rb("x = <<~E if y\n  t\nE\nz = 'q'", "C{x = <<~E if y\n}S*#{  t\nE}C{\nz = }S{'q'}");
	rb("foo <<A\nb\nA\n", "C{foo <<A\n}S*#{b\nA}C{\n}");
	rb("foo <<~A, 'x'\n  b\n  A\nz", "C{foo <<~A, }S{'x'}C{\n}S*#{  b\n  A}C{\nz}");
	rb("p(<<A)\nb\nA\n", "C{p(<<A)\n}S*#{b\nA}C{\n}");
	rb("puts <<A\nb\nA", "C{puts <<A\n}S*#{b\nA}");
	rb("puts <<A\nb\nA\n=begin\nc\n=end\nd", "C{puts <<A\n}S*#{b\nA}C{\n}K{=begin\nc\n=end}C{\nd}");
	rb("x = <<A\n\\\nA\nb\nA\ny = 'q'", "C{x = <<A\n}S*#{\\\nA\nb\nA}C{\ny = }S{'q'}");
	/* not confirmed: no program: not closed */
	rbx("puts <<A\nno end", "C{puts <<A\n}S*!#{no end}");
	rbx("x = <<A\nb\n", "C{x = <<A\n}S*!#{b\n}");
	rbx("x = <<-A\n  b\nA x\n", "C{x = <<-A\n}S*!#{  b\nA x\n}");
	rbx("x = <<A\nb\n#{", "C{x = <<A\n}S!#{b\n#{}");
	rbx("x = <<'A\nb\nA", "C{x = <<}S!{'A\nb\nA}");
	/* not confirmed: a name the interpreter knows is a variable */
	rbx("x = 1\ny = x <<z\nA\n", "C{x = 1\ny = x <<z\n}S*!#{A\n}");
	/* not confirmed: the oracle ends the body at the inner heredoc's closing line; the body is every line through its own */
	rbx("x = <<A\n#{ \"\n#{<<B}\nb\nB\n\" }\nA\ny", "C{x = <<A\n}S#{#{ \"\n#{<<B}\nb\nB\n\" }\nA}C{\ny}");
	/* shift or heredoc */
	rb("x << y", "C{x << y}");
	rb("x<<y", "C{x<<y}");
	rb("x = y << 2", "C{x = y << 2}");
	rb("x = (y) << 2", "C{x = (y) << 2}");
	rb("x = a[0] << 1", "C{x = a[0] << 1}");
	rb("x = 1 <<2", "C{x = 1 <<2}");
	rb("x = y.z << 3", "C{x = y.z << 3}");
	rb("puts(x << \"a\")", "C{puts(x << }S*{\"a\"}C{)}");
	rb("x << \"a\" << 'b'", "C{x << }S*{\"a\"}C{ << }S{'b'}");
	rb("a <<= 2", "C{a <<= 2}");
	rb("class << self\n  def a; end\nend", "C{class << self\n  def a; end\nend}");
	rb("class <<self\nend", "C{class <<self\nend}");
	rb("x = [1] << 2", "C{x = [1] << 2}");
	rb("x = 1 << 2 << 3", "C{x = 1 << 2 << 3}");
	rb("obj.<<(y)", "C{obj.<<(y)}");
	rb("def <<(x); end", "C{def <<(x); end}");
	rb("x = y <<\"A\"\nb\nA\n", "C{x = y <<\"A\"\n}S*#{b\nA}C{\n}");
	/* not confirmed: no program: x is read as a name taking a heredoc, which is not closed (ripper reports the error and has no end) */
	rbx("x <<\"a\"\nb", "C{x <<\"a\"\n}S*!#{b}");
	/* operator method names */
	rb("def /(x) end", "C{def /(x) end}");
	rb("def %(x) end", "C{def %(x) end}");
	rb("def <<(x) end", "C{def <<(x) end}");
	rb("def `(c) end", "C{def `(c) end}");
	rb("def -@; end", "C{def -@; end}");
	rb("def ==(o); end", "C{def ==(o); end}");
	rb("def []=(k, v); end", "C{def []=(k, v); end}");
	rb("def self./(x); end", "C{def self./(x); end}");
	rb("x./(2)", "C{x./(2)}");
	rb("x.%(3)", "C{x.%(3)}");
	rb("x.<<(4)", "C{x.<<(4)}");
	rb("x.`(\"ls\")", "C{x.`(}S*{\"ls\"}C{)}");
	rb("alias :+ :-", "C{alias :+ :-}");
	rb("undef /", "C{undef /}");
	rb("alias / %", "C{alias / %}");
	rb("alias x? y!", "C{alias x? y!}");
	rb("def a=(v) end", "C{def a=(v) end}");
	rb("def self.a=(v) end", "C{def self.a=(v) end}");
	rb("def a /re/ end", "C{def a /re/ end}");
	rb("def f(a) /re/ end", "C{def f(a) }S{/re/}C{ end}");
	rb("def f(a, b = 1) %w[a] end", "C{def f(a, b = 1) }S{%w[a]}C{ end}");
	rb("def f() /re/ end", "C{def f() }S{/re/}C{ end}");
	rb("def x.y(a) /re/ end", "C{def x.y(a) }S{/re/}C{ end}");
	/* names and keywords */
	rb("puts if: 1", "C{puts if: 1}");
	rb("x = {if: 1, \"else\": 2}", "C{x = {if: 1, }S*{\"else\"}C{: 2}}");
	rb("return /a/", "C{return }S{/a/}");
	rb("when_ = 1", "C{when_ = 1}");
	rb("x and /a/", "C{x and }S{/a/}");
	rb("x or %w[a]", "C{x or }S{%w[a]}");
	rb("yield /a/", "C{yield }S{/a/}");
	rb("end / 2", "C{end / 2}");
	rb("self / 2", "C{self / 2}");
	rb("nil % 2", "C{nil % 2}");
	rb("true ? 1 : 2", "C{true ? 1 : 2}");
	rb("x.class /a/", "C{x.class }S{/a/}");
	rb("x.end / 2", "C{x.end / 2}");
	rb("x = a.b.c %w[a]", "C{x = a.b.c }S{%w[a]}");
	rb("x::Y /a/", "C{x::Y }S{/a/}");
	rb("A::B /a/", "C{A::B }S{/a/}");
	rb("::A / 2", "C{::A / 2}");
	rb("foo?(x) ? 1 : 2", "C{foo?(x) ? 1 : 2}");
	rb("foo!(x) / 2", "C{foo!(x) / 2}");
	rb("@a / 2", "C{@a / 2}");
	rb("@@a / 2", "C{@@a / 2}");
	rb("$a / 2", "C{$a / 2}");
	rb("1 / 2", "C{1 / 2}");
	rb("1.5 / 2", "C{1.5 / 2}");
	rb("0x1f / 2", "C{0x1f / 2}");
	rb("x = a.b ? c.d : e.f", "C{x = a.b ? c.d : e.f}");
	rb("BEGIN { puts \"x\" }", "C{BEGIN { puts }S*{\"x\"}C{ }}");
	rb("END { puts 'y' }", "C{END { puts }S{'y'}C{ }}");
	rb("defined? x", "C{defined? x}");
	rb("defined?(x) && /a/", "C{defined?(x) && }S{/a/}");
	rb("\xc3\xa9 = 1", "C{\xc3\xa9 = 1}");
	rb("x = \xc3\xa9 / 2", "C{x = \xc3\xa9 / 2}");
	rb("puts \xc3\xa9 ? 1 : 2", "C{puts \xc3\xa9 ? 1 : 2}");
	/* not confirmed: the interpreter knows what the name is */
	rbx("\xc3\xa9 = 1\nx = \xc3\xa9 /2\ny = 'q'", "C{\xc3\xa9 = 1\nx = \xc3\xa9 }S!{/2\ny = 'q'}");
	rbx("x = 1\nx /2\n", "C{x = 1\nx }S!{/2\n}");
	/* continuations */
	rb("x = 1 + \\\n2", "C{x = 1 + \\\n2}");
	rb("x = \"a\" \\\n\"b\"", "C{x = }S*{\"a\"}C{ \\\n}S*{\"b\"}");
	rb("x = 1 + \\\r\n2", "C{x = 1 + \\\r\n2}");
	rb("x = 1 \\\n# c\ny", "C{x = 1 \\\n}K{# c}C{\ny}");
	rb("x = \"a\" \\\n  'b'", "C{x = }S*{\"a\"}C{ \\\n  }S{'b'}");
	rb("x = <<A + \\\n  'z'\nb\nA\n", "C{x = <<A + \\\n}S*#{  'z'\nb\nA}C{\n}");
	rb("puts 1,\n  2", "C{puts 1,\n  2}");
	/* not confirmed: no program: a backslash that is not a continuation */
	rbx("x = \\\"a\"", "C{x = \\\"a}S*!{\"}");
	rbx("x = \\#c\ny", "C{x = \\#c\ny}");
	rbx("\\", "C{\\}");
	/* lines */
	rb("a\r\nb = \"c\r\nd\"\r\n", "C{a\r\nb = }S*{\"c\r\nd\"}C{\r\n}");
	rb("a\rb = 'c'", "C{a\rb = }S{'c'}");
	rb("a\n\n\nb = \"c\"", "C{a\n\n\nb = }S*{\"c\"}");
	rb("x = 'a'\r\n# c\r\ny = \"b\"", "C{x = }S{'a'}C{\r\n}K{# c}C{\r\ny = }S*{\"b\"}");
	rb("x = 'a' # c\r\n", "C{x = }S{'a'}C{ }K{# c}C{\r\n}");
	rb("\fx = 1\t# c\n\t\"a\"", "C{\fx = 1\t}K{# c}C{\n\t}S*{\"a\"}");
	rb("x = 1;y = 'a';z = \"b\"", "C{x = 1;y = }S{'a'}C{;z = }S*{\"b\"}");
	/* unicode */
	rb("x = '\xc3\xa9\xe2\x82\xac' + \"\xf0\x9f\x98\x80\"", "C{x = }S{'\xc3\xa9\xe2\x82\xac'}C{ + }S*{\"\xf0\x9f\x98\x80\"}");
	rb("# \xc3\xa9\nx = \"\xc3\xa9\"", "K{# \xc3\xa9}C{\nx = }S*{\"\xc3\xa9\"}");
	rb("\xc3\xa9 = \"a\"", "C{\xc3\xa9 = }S*{\"a\"}");
	rb("x = \"\xff\xfe\"", "C{x = }S*{\"\xff\xfe\"}");
	rb("x = ?\xc3\xa9", "C{x = ?\xc3\xa9}");
	rb("x = %w[\xc3\xa9 b]", "C{x = }S{%w[\xc3\xa9 b]}");
}

#endif /* KGENOME_TEST_TEXTUAL_RUBY_CASES_H */
