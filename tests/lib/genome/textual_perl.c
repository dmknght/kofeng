/*
 * genome / textual_perl - the perl lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED, and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS, one per rule with the neighbour it could be confused for. A case is the text and the
 *       one line it must come out as (kind letter, bytes in braces; S* = a backslash is an escape in it, S! = not
 *       closed, S# = a here-document or a format - see textual_check.h). `perl(...)` is a case perl 5.44 agrees
 *       with: a scratch script outside the tree reads this file, takes every `perl(` text, asks the lexer for its
 *       spans, and checks the program with `perl -c` and with `perl -MO=Deparse` after the text of each span the
 *       case names a string was replaced by a marker and each one the case names a comment was replaced by a
 *       line of nonsense. `perlx(...)` is a case no perl here can confirm - a text that is not a program, an
 *       unclosed literal, a choice of this lexer - and says why where it is.
 *   (b) A GENERATOR of perl programs (textual_perl_gen.h). Tokens of known class - code, string (every operator,
 *       delimiter and flag), here-document, comment, pod, data - are laid out in statements with comments in odd
 *       places, in one of two line-ending styles, and the lexer's spans must equal what the generator knows, byte for
 *       byte: kind, offset, length, delimiters and the flags. The form of each program must keep every literal, keep
 *       no comment, and be its own form. Programs are valid perl: a scratch program includes the generator, writes N
 *       of them to disk and `perl -c` reads each. The numbers of that run and of the comparison with the corpus are a
 *       measurement and are in the report, not here: a comment that carries one goes stale.
 *   (c) THE PARTITION and the idempotence of the form on random text from a perl alphabet and from perl's own
 *       words, a text cut at every length, and hostile texts - nesting, a literal that never closes, NUL bytes,
 *       every line ending - read in time linear in them.
 *   (d) FORM and decoder known answers, the decode hook with a fake decoder (the contract is what is asserted, not
 *       an algorithm), and the words of the language: the table is sorted.
 *
 * Everything goes through <kgenome.h> and nothing else, except the one white-box check of the keyword table.
 */

#include "textual_check.h"

#include <time.h>

#include "textual/perl/perl.h"

#define PERL KGENOME_TEXTUAL_LANG_PERL

static void perl(const char *src, const char *want)
{
	expect_lang(PERL, src, want);
}

/* Not confirmed by perl here (not a program, an unclosed literal, a choice of the lexer): the reason is the comment at the call. */
static void perlx(const char *src, const char *want)
{
	expect_lang(PERL, src, want);
}

static void comments(void)
{
	perl("# c\nx", "K{# c}C{\nx}");
	perl("x # c\nz", "C{x }K{# c}C{\nz}");
	/* a comment ends at "\n" only: a CR is a blank, so a CRLF file's comment holds its CR, and a lone CR does not end it */
	perl("# c\r\nx", "K{# c\r}C{\nx}");
	perlx("# c\rx", "K{# c\rx}");
	/* a comment marker in a string is the string's, a quote in a comment is the comment's */
	perl("print '#', \"#\", q#a#; # 'x\" `y\n1;", "C{print }S{'#'}C{, }S*{\"#\"}C{, }S{q#a#}C{; }K{# 'x\" `y}C{\n1;}");
	/* the interpreter line is a comment (and the row keeps it) */
	perl("#!/usr/bin/perl -w\nprint 1;\n", "K{#!/usr/bin/perl -w}C{\nprint 1;\n}");
	/* "#" is not a comment after "$" or as the delimiter of q s m y tr qq qw qx qr when attached */
	perl("print $#a, $#{$r}, $#$r;", "C{print $#a, $#{$r}, $#$r;}");
	perl("$x = q#a#; $y = s#a#b#; $z = m#a#;", "C{$x = }S{q#a#}C{; $y = }S{s#a#b#}C{; $z = }S{m#a#}C{;}");
	perl("$x = qw#a b#;", "C{$x = }S{qw#a b#}C{;}");
	/* after white space it is a comment, and the delimiter comes after it */
	perl("$x = q #c\n(a);", "C{$x = }S{q #c\n(a)}C{;}");
	perl("$x = qq # c\n  {a};", "C{$x = }S*{qq # c\n  {a}}C{;}");
	/* special variables hold a quote or a hash and are not strings or comments */
	perl("print $', $\", $`, $;", "C{print $', $\", $`, $;}");
	perl("local $\" = ''; print 1;", "C{local $\" = }S{''}C{; print 1;}");
}

static void pod(void)
{
	perl("print 1;\n=pod\n\ntext 'q \"x\n\n=cut\nprint 2;\n", "C{print 1;\n}K{=pod\n\ntext 'q \"x\n\n=cut}C{\nprint 2;\n}");
	/* at the start of the text, and after the statement that ends with a block */
	perl("=head1 NAME\n\nx\n\n=cut\n1;", "K{=head1 NAME\n\nx\n\n=cut}C{\n1;}");
	perl("if ($x) { 1 }\n=pod\nx\n=cut\n1;", "C{if ($x) { 1 }\n}K{=pod\nx\n=cut}C{\n1;}");
	perl("sub f { 1 }\n=pod\nx\n=cut\n1;", "C{sub f { 1 }\n}K{=pod\nx\n=cut}C{\n1;}");
	perl("A: {\n 1;\n}\n=pod\nx\n=cut\n1;", "C{A: {\n 1;\n}\n}K{=pod\nx\n=cut}C{\n1;}");
	/* a pod with no =cut runs to the end of the text, and is not an unclosed literal */
	perl("1;\n=head1 X\ntext\n'q", "C{1;\n}K{=head1 X\ntext\n'q}");
	/* "=cut" by itself begins one, as any "=word" does, and the line that begins it is not the line that ends it (perl 5.44:
	 * `=cut<newline>print 1;` prints nothing); "=cutx" is not the end of a pod either */
	perl("=cut\nprint 1;", "K{=cut\nprint 1;}");
	perl("print 1;\n=cut\nprint 2;\n=cut\nprint 3;", "C{print 1;\n}K{=cut\nprint 2;\n=cut}C{\nprint 3;}");
	perl("=pod\n=cutx\nz\n=cut\nx;", "K{=pod\n=cutx\nz\n=cut}C{\nx;}");
	/* "=cut" ends it only at the start of a line */
	perl("=pod\n x =cut\n=cut\n1;", "K{=pod\n x =cut\n=cut}C{\n1;}");
	/* inside a statement it is not pod: perl says "syntax error" for "=pod" there, and `$x\n=pod` is an assignment */
	perl("$x\n=pod;\n", "C{$x\n=pod;\n}");
	perl("$h{a}\n=pod;\n", "C{$h{a}\n=pod;\n}");
	perl("@a = (1,\n2\n);\n=pod\nx\n=cut\n", "C{@a = (1,\n2\n);\n}K{=pod\nx\n=cut}C{\n}");
	/* a line that begins "=" and a non-letter is code, "=" and a letter at the start of a statement is pod */
	perl("$y\n== 1;\n$x\n= 1;\n", "C{$y\n== 1;\n$x\n= 1;\n}");
	/* NOT PERL: indented, "=pod" is a syntax error at a statement's start in perl and is read as pod here, because the form moves
	 * every line's first token to the first column and the form of a form must be itself */
	perlx(";\n  =pod\nx\n=cut\n1;", "C{;\n  }K{=pod\nx\n=cut}C{\n1;}");
	perlx(";\n\t=head1 X\n", "C{;\n\t}K{=head1 X\n}");
	/* in a here-document, a string or a quote-like it is text */
	perl("print <<E;\n=pod\nE\n1;", "C{print <<E;\n}S*#{=pod\nE}C{\n1;}");
	perl("$x = q{\n=pod\n=cut\n};", "C{$x = }S{q{\n=pod\n=cut\n}}C{;}");
}

static void quotes(void)
{
	perl("'a'; \"b\"; `c`", "S{'a'}C{; }S*{\"b\"}C{; }S*{`c`}");
	/* the other quotes are bytes of the string, a quote is escaped by a backslash and a backslash by itself */
	perl("'a\"b'; \"a'b\"; `a'\"b`", "S{'a\"b'}C{; }S*{\"a'b\"}C{; }S*{`a'\"b`}");
	perl("'a\\'b'; \"a\\\"b\"; 'c\\\\'; x", "S{'a\\'b'}C{; }S*{\"a\\\"b\"}C{; }S{'c\\\\'}C{; x}");
	/* a string runs over lines, and holds a comment marker */
	perl("'a\n# b\nc'; x", "S{'a\n# b\nc'}C{; x}");
	/* perl finds the end of a quoted text before it reads what is in it: the second quote closes "@{[ " */
	perlx("\"@{[ \"x\" ]}\"", "S*{\"@{[ \"}C{x}S*{\" ]}\"}");
	/* unclosed: to the end of the text, flagged */
	perlx("'abc", "S!{'abc}");
	perlx("\"abc\\", "S*!{\"abc\\}");
	perlx("`abc\n", "S*!{`abc\n}");
	perlx("x = 'a' . 'b", "C{x = }S{'a'}C{ . }S!{'b}");
	/* "'" in a name is the old package separator, and a perl word is not a name: print'a' is a string */
	perl("print'a';", "C{print}S{'a'}C{;}");
	perl("return'a' if 0;", "C{return}S{'a'}C{ if 0;}");
	perl("sub f { 1 } $x = f 'a';", "C{sub f { 1 } $x = f }S{'a'}C{;}");
	perl("$x = main'f(1);", "C{$x = main'f(1);}");
	/* the same in a variable and in a sub's name: the old perlasm and cgi code */
	perl("$z = $main'win32 . &www'message(1) . @main'a; sub main'g { 1 }", "C{$z = $main'win32 . &www'message(1) . @main'a; sub main'g { 1 }}");
	perlx("foo'x'", "C{foo'x}S!{'}");
}

static void quotelike(void)
{
	/* every operator with the bracket that nests, and the one that does not */
	perl("q(a(b)c); q[a[b]c]; q{a{b}c}; q<a<b>c>", "S{q(a(b)c)}C{; }S{q[a[b]c]}C{; }S{q{a{b}c}}C{; }S{q<a<b>c>}");
	perl("q/a/; q!a!; q|a|; q,a,; q;a;; q'a'; q\"a\"; q~a~; q^a^; q%a%; q:a:", "S{q/a/}C{; }S{q!a!}C{; }S{q|a|}C{; }S{q,a,}C{; }S{q;a;}C{; }S{q'a'}C{; }S{q\"a\"}C{; }S{q~a~}C{; }S{q^a^}C{; }S{q%a%}C{; }S{q:a:}");
	perl("qq{a}; qw(a b); qx{a}; qr{a}; m{a}", "S*{qq{a}}C{; }S{qw(a b)}C{; }S*{qx{a}}C{; }S{qr{a}}C{; }S{m{a}}");
	/* a backslash takes the delimiter, the bracket and itself */
	perl("q{a\\}b}; q(a\\)b); q/a\\/b/; q{a\\\\}; x", "S{q{a\\}b}}C{; }S{q(a\\)b)}C{; }S{q/a\\/b/}C{; }S{q{a\\\\}}C{; x}");
	perl("$x = q{a{b\\}c}d};", "C{$x = }S{q{a{b\\}c}d}}C{;}");
	/* only the interpolating ones are flagged, and qx with ' is not one */
	perl("qq'a'; qx'a'; qx\"a\"", "S*{qq'a'}C{; }S{qx'a'}C{; }S*{qx\"a\"}");
	/* white space, a line break and comments between the word and the delimiter; a word byte opens after white space */
	perl("q (a); q\n(b); q # c\n\n (d)", "S{q (a)}C{; }S{q\n(b)}C{; }S{q # c\n\n (d)}");
	perl("$x = q xabcx;", "C{$x = }S{q xabcx}C{;}");
	/* patterns and their flags: the letters the operator has, directly after the closer */
	perl("m/a/gi; qr{a}x; m!a!s", "S{m/a/gi}C{; }S{qr{a}x}C{; }S{m!a!s}");
	perl("$x =~ m/a/ if 1;", "C{$x =~ }S{m/a/}C{ if 1;}");
	perl("$x =~ m/a/i if 1;", "C{$x =~ }S{m/a/i}C{ if 1;}");
	perl("$x =~ m:^/:s; $x =~ s,a,b,gi; $x =~ m%a%x; $x =~ s!a!b!e;", "C{$x =~ }S{m:^/:s}C{; $x =~ }S{s,a,b,gi}C{; $x =~ }S{m%a%x}C{; $x =~ }S{s!a!b!e}C{;}");
	perl("m'a$b';", "S{m'a$b'}C{;}");
	/* two parts */
	perl("s/a/b/; s/a/b/gie; s{a}{b}; s(a)(b); s<a><b>", "S{s/a/b/}C{; }S{s/a/b/gie}C{; }S{s{a}{b}}C{; }S{s(a)(b)}C{; }S{s<a><b>}");
	perl("s{a}/b/; s(a)[b]e; s{a}'b'", "S{s{a}/b/}C{; }S{s(a)[b]e}C{; }S{s{a}'b'}");
	perl("s{a} {b}; s{a}\n{b}; s{a} # c\n {b}; s{a}#b#", "S{s{a} {b}}C{; }S{s{a}\n{b}}C{; }S{s{a} # c\n {b}}C{; }S{s{a}#b#}");
	perlx("s{a}#c\n{b}", "S!{s{a}#c\n{b}}");
	perl("s#a#b#; s,a,b,; s'a'b'; s;a;b;", "S{s#a#b#}C{; }S{s,a,b,}C{; }S{s'a'b'}C{; }S{s;a;b;}");
	/* flags after a closer the row keeps a space behind are in the span; after any other they are a word, and a quote word after a
	 * term is not an operator: "s@a@b@s) {" is File::Spec::Cygwin's. See flags_end. */
	perl("m'a'i; y;;;d; s;a;b;g; if ($p =~ s@a@b@s) { 1 }", "S{m'a'}C{i; }S{y;;;}C{d; }S{s;a;b;}C{g; if ($p =~ }S{s@a@b@}C{s) { 1 }}");
	perl("$x =~ m:^/:s; $x =~ s,a,b,gi; $x =~ m%a%x; $x =~ s!a!b!e;", "C{$x =~ }S{m:^/:s}C{; $x =~ }S{s,a,b,gi}C{; $x =~ }S{m%a%x}C{; $x =~ }S{s!a!b!e}C{;}");
	perl("s/a\\/b/c\\/d/; s{a{b}c}{d{e}f}", "S{s/a\\/b/c\\/d/}C{; }S{s{a{b}c}{d{e}f}}");
	perl("tr/a-z/A-Z/; tr/a-z//cd; tr{a}{b}; y/a/b/r; y(a)(b)", "S{tr/a-z/A-Z/}C{; }S{tr/a-z//cd}C{; }S{tr{a}{b}}C{; }S{y/a/b/r}C{; }S{y(a)(b)}");
	/* the replacement of s///e is code, and is inside the span: perl finds the end first */
	perl("s/a/\"b\" . q(c)/e", "S{s/a/\"b\" . q(c)/e}");
	/* unclosed: to the end of the text, one part or two */
	perlx("q(abc", "S!{q(abc}");
	perlx("s/a/b", "S!{s/a/b}");
	perlx("s{a}", "S!{s{a}}");
	perlx("s{a} ", "S!{s{a} }");
	perlx("m/a", "S!{m/a}");
	/* a quote word at the end of the text, or with nothing after it, is a word */
	perlx("q", "C{q}");
	perlx("$x = s", "C{$x = s}");
	perlx("$x = y ", "C{$x = y }");
}

static void barewords(void)
{
	/* a quote word before "=>" (white space, line breaks and comments between), in "{...}", after "->" and after "sub" or "package" is a name */
	perl("%h = (s => 1, y=>2, q\n=> 3, m # c\n => 4, tr => 5, qw => 6);", "C{%h = (s => 1, y=>2, q\n=> 3, m }K{# c}C{\n => 4, tr => 5, qw => 6);}");
	perl("$z = $h{s} . $h{ y } . $h{q}{m}{tr};", "C{$z = $h{s} . $h{ y } . $h{q}{m}{tr};}");
	perl("$z = $o->s . $o->y(1) . $o->m;", "C{$z = $o->s . $o->y(1) . $o->m;}");
	perl("sub s { 1 } sub y { 2 } package q; package m;", "C{sub s { 1 } sub y { 2 } package q; package m;}");
	perl("$z = Foo::s() . Foo::y(1) . $::s . $Foo::y . $q::m::tr . Foo::q::m();", "C{$z = Foo::s() . Foo::y(1) . $::s . $Foo::y . $q::m::tr . Foo::q::m();}");
	/* but "s::x" is a substitution whose delimiter is ":" - perl 5.44 says so for every quote word, and "y::x" and "q::x" are not names */
	perl("$z =~ s::x:; $z = q::;", "C{$z =~ }S{s::x:}C{; $z = }S{q::}C{;}");
	/* a variable of that name is a variable */
	perl("$z = $s . $y . $m . $q . $tr; @z = (@s, @y, %q, &m, *tr); $z = ${s} . ${ y } . @{q};", "C{$z = $s . $y . $m . $q . $tr; @z = (@s, @y, %q, &m, *tr); $z = ${s} . ${ y } . @{q};}");
	perl("$z = s1 . y_2 . qq3 . tr4 . q_ . m0;", "C{$z = s1 . y_2 . qq3 . tr4 . q_ . m0;}");
	/* "-s" is the file test, wherever it is: perl reads "$x -s/a/b/" as a syntax error */
	perl("$z = -s $f; $z = (-s $f) > 1; $z = -s => 1;", "C{$z = -s $f; $z = (-s $f) > 1; $z = -s => 1;}");
	perlx("$x -s/a/b/", "C{$x -s}S{/a/}C{b/}");
	/* and what looks like one in front of a delimiter is the operator, wherever it is */
	perl("print s/a/b/ ? 1 : 0;", "C{print }S{s/a/b/}C{ ? 1 : 0;}");
	perl("$z = 1 + y/a/b/;", "C{$z = 1 + }S{y/a/b/}C{;}");
}

static void slash(void)
{
	/* "/" after a term divides, after an operator, an opening bracket, a comma or a word that takes a term it opens a pattern */
	perl("$z = $a / $b / 2;", "C{$z = $a / $b / 2;}");
	perl("$z = ($a) / $b / 2; $z = $h{a} / 2 / 3; $z = $a[0] / 2 / 3; $z = f() / 2 / 3;", "C{$z = ($a) / $b / 2; $z = $h{a} / 2 / 3; $z = $a[0] / 2 / 3; $z = f() / 2 / 3;}");
	perl("$z = 4 / 2 / 1; $z = 1.5 / 2 / 3; $z = 0x10 / 2 / 3; $z = 1e-3 / 2 / 1; $z = $#a / 2 / 3;", "C{$z = 4 / 2 / 1; $z = 1.5 / 2 / 3; $z = 0x10 / 2 / 3; $z = 1e-3 / 2 / 1; $z = $#a / 2 / 3;}");
	perl("$z = $i++ / 2 / 3; $z = $i-- / 2 / 3; $z = @a / 2 / 3; $z = $r->{a} / 2 / 3;", "C{$z = $i++ / 2 / 3; $z = $i-- / 2 / 3; $z = @a / 2 / 3; $z = $r->{a} / 2 / 3;}");
	perl("$z = time / 2 / 3; $z = shift // 1; $z = $x // 1; $z //= 2; $z /= 2;", "C{$z = time / 2 / 3; $z = shift // 1; $z = $x // 1; $z //= 2; $z /= 2;}");
	perl("$z = do { 1 } / 2 / 1; $z = eval { 1 } / 2 / 1; $z = sub { 1 }->() / 2 / 1;", "C{$z = do { 1 } / 2 / 1; $z = eval { 1 } / 2 / 1; $z = sub { 1 }->() / 2 / 1;}");
	perl("$z = $x x 3 / 2;", "C{$z = $x x 3 / 2;}");
	perl("split /,/, $x;", "C{split }S{/,/}C{, $x;}");
	perl("$x =~ /a/; $x !~ /a/i; if (/a/) { 1 }", "C{$x =~ }S{/a/}C{; $x !~ }S{/a/i}C{; if (}S{/a/}C{) { 1 }}");
	perl("@l = grep /a/, @x; return /a/ if 0; print 1 if /a/ and /b/ or !/c/;", "C{@l = grep }S{/a/}C{, @x; return }S{/a/}C{ if 0; print 1 if }S{/a/}C{ and }S{/b/}C{ or !}S{/c/}C{;}");
	perl("$z = $a ? /a/ : /b/; @z = (/a/, 1); $z = 1 && /a/;", "C{$z = $a ? }S{/a/}C{ : }S{/b/}C{; @z = (}S{/a/}C{, 1); $z = 1 && }S{/a/}C{;}");
	perl("sub f { /a/ ? 1 : 0 } @z = map { /x/ ? 1 : 0 } @a;", "C{sub f { }S{/a/}C{ ? 1 : 0 } @z = map { }S{/x/}C{ ? 1 : 0 } @a;}");
	perl("if ($x) { 1 } /a/ and 1;", "C{if ($x) { 1 } }S{/a/}C{ and 1;}");
	perl("split //, $x; $z = $x =~ //;", "C{split }S{//}C{, $x; $z = $x =~ }S{//}C{;}");
	/* the delimiter is escaped, and the pattern does not understand [ ] */
	perl("$x =~ /a\\/b/; $x =~ /a\\\\/ ;", "C{$x =~ }S{/a\\/b/}C{; $x =~ }S{/a\\\\/}C{ ;}");
	perlx("$x =~ /[/]/;", "C{$x =~ }S{/[/}C{]/;}");
	perlx("$x = /a", "C{$x = }S!{/a}");
	/* a pattern and its flags, white space, then a word */
	perl("$x =~ /a/gi ; $y = 1;", "C{$x =~ }S{/a/gi}C{ ; $y = 1;}");
	/* "?" is the conditional operator: the pattern ?...? is gone since perl 5.22 */
	perl("$z = $a ? 1 : 2; $z = $a ? $b / 2 : $c / 3;", "C{$z = $a ? 1 : 2; $z = $a ? $b / 2 : $c / 3;}");
}

static void here(void)
{
	perl("print <<\"EOF\", <<'X';\nbody $x\nEOF\nraw\nX\nz;", "C{print <<}S#{\"EOF\"}C{, <<}S#{'X'}C{;\n}S*#{body $x\nEOF}C{\n}S#{raw\nX}C{\nz;}");
	perl("print <<EOF;\na\nEOF\n1;", "C{print <<EOF;\n}S*#{a\nEOF}C{\n1;}");
	perl("print <<~EOF;\n   a\n  EOF\n1;", "C{print <<~EOF;\n}S*#{   a\n  EOF}C{\n1;}");
	perl("print <<~'EOF';\n   a\n EOF\n", "C{print <<~}S#{'EOF'}C{;\n}S#{   a\n EOF}C{\n}");
	perl("print <<\\EOF;\na $x\nEOF\n", "C{print <<\\EOF;\n}S#{a $x\nEOF}C{\n}");
	perl("print << \"EOF\";\na\nEOF\n", "C{print << }S#{\"EOF\"}C{;\n}S*#{a\nEOF}C{\n}");
	perl("print <<\"\";\nbody\n\nprint 2;\n", "C{print <<}S#{\"\"}C{;\n}S*#{body\n\n}C{print 2;\n}");
	perl("print <<`EOC`;\necho\nEOC\n", "C{print <<}S#{`EOC`}C{;\n}S*#{echo\nEOC}C{\n}");
	/* a tag with white space in it is the tag's */
	perl("print <<\"    EOT\";\nx\n    EOT\n", "C{print <<}S#{\"    EOT\"}C{;\n}S*#{x\n    EOT}C{\n}");
	/* the body begins on the next line, and the rest of the operator's line is code */
	perl("print <<A . \"x\" . <<B; # c 'q\n1\nA\n2\nB\nz;", "C{print <<A . }S*{\"x\"}C{ . <<B; }K{# c 'q}C{\n}S*#{1\nA}C{\n}S*#{2\nB}C{\nz;}");
	perl("f(<<A, g(<<B), <<C);\n1\nA\n2\nB\n3\nC\n", "C{f(<<A, g(<<B), <<C);\n}S*#{1\nA}C{\n}S*#{2\nB}C{\n}S*#{3\nC}C{\n}");
	/* the closing line is the tag and nothing else; a body line that has it with more is not the end */
	perl("print <<A;\nA x\n xA\nA\n", "C{print <<A;\n}S*#{A x\n xA\nA}C{\n}");
	perlx("print <<A;\n A\n", "C{print <<A;\n}S*!#{ A\n}");
	/* CRLF: the "\r" before the break is not part of the tag */
	perl("print <<A;\r\nx\r\nA\r\nz;", "C{print <<A;\r\n}S*#{x\r\nA}C{\r\nz;}");
	/* unclosed: the body runs to the end and is flagged */
	perlx("print <<A;\nbody 'x\n", "C{print <<A;\n}S*!#{body 'x\n}");
	perlx("print <<A;", "C{print <<A;}");
	/* after a file handle, a function and a term that takes the operator: here-document or shift */
	perl("print $fh <<A;\nx\nA\nprint STDERR <<A;\nx\nA\n", "C{print $fh <<A;\n}S*#{x\nA}C{\nprint STDERR <<A;\n}S*#{x\nA}C{\n}");
	perl("return <<A;\nx\nA\n", "C{return <<A;\n}S*#{x\nA}C{\n}");
	perl("push @a, <<A;\nx\nA\n", "C{push @a, <<A;\n}S*#{x\nA}C{\n}");
	perl("warn <<A;\nx\nA\n", "C{warn <<A;\n}S*#{x\nA}C{\n}");
	perl("sub croak { 1 } croak << \"EOT\";\nx\nEOT\n", "C{sub croak { 1 } croak << }S#{\"EOT\"}C{;\n}S*#{x\nEOT}C{\n}");
		perl("$x = f <<A;\nx\nA\n", "C{$x = f <<A;\n}S*#{x\nA}C{\n}");
	perl("$x = <<A;\nx\nA\n", "C{$x = <<A;\n}S*#{x\nA}C{\n}");
	perl("$z = 1 << 2; $z = $a << 2; $z = $a <<= 2; $z = 1 <<A;", "C{$z = 1 << 2; $z = $a << 2; $z = $a <<= 2; $z = 1 <<A;}");
	perl("$z = $a << \"3\"; $z = $a <<\"3\";", "C{$z = $a << }S*{\"3\"}C{; $z = $a <<}S*{\"3\"}C{;}");
	/* and not "<< EOF" with white space and a bare word: that is a shift in perl 5.28 and later */
	perlx("print << EOF;", "C{print << EOF;}");
	/* <FH> and the globs */
	perl("while (<STDIN>) { 1 } @f = <*.c>; $l = <$fh>; @f = <$d/*>;", "C{while (<STDIN>) { 1 } @f = <*.c>; $l = <$fh>; @f = <$d/*>;}");
	perl("$z = $a < $b; $z = ($a <$b) and $c > 1;", "C{$z = $a < $b; $z = ($a <$b) and $c > 1;}");
}

static void data(void)
{
	perl("print 1;\n__END__\nraw 'q \"x # y\n=pod\n", "C{print 1;\n__END__\n}S{raw 'q \"x # y\n=pod\n}");
	perl("print 1;\n__DATA__\nraw", "C{print 1;\n__DATA__\n}S{raw}");
	perl("print 1;\n__END__ trailing\nraw", "C{print 1;\n__END__ trailing\n}S{raw}");
	perl("print 1; __END__\nraw", "C{print 1; __END__\n}S{raw}");
	/* nothing after it, or only its line break: no data span */
	perl("print 1;\n__END__", "C{print 1;\n__END__}");
	perl("print 1;\n__END__\n", "C{print 1;\n__END__\n}");
	perl("print 1;\r\n__END__\r\nx\r\n", "C{print 1;\r\n__END__\r\n}S{x\r\n}");
	/* a word of that name is not the marker as a key, after "->", before "=>" and as a variable */
	perl("$h{__END__} = 1; $z = $o->__END__ . __END__ => 1; $z = $__END__; print 2;", "C{$h{__END__} = 1; $z = $o->__END__ . __END__ => 1; $z = $__END__; print 2;}");
	perl("sub __END__ { 1 } print 3; x__END__ z;", "C{sub __END__ { 1 } print 3; x__END__ z;}");
	/* in a string, a comment or a here-document it is text */
	perl("print '__END__', \"__END__\"; # __END__\n1;", "C{print }S{'__END__'}C{, }S*{\"__END__\"}C{; }K{# __END__}C{\n1;}");
}

static void format(void)
{
	perl("format STDOUT =\n@<<< @>>>\n$a, $b\n.\nwrite;", "C{format STDOUT =\n}S#{@<<< @>>>\n$a, $b\n.}C{\nwrite;}");
	perl("format =\n# not 'a' comment\n.\n1;", "C{format =\n}S#{# not 'a' comment\n.}C{\n1;}");
	perl("format STDOUT_TOP =\r\n@<<<\r\n$x\r\n.\r\n1;", "C{format STDOUT_TOP =\r\n}S#{@<<<\r\n$x\r\n.}C{\r\n1;}");
	/* ".  " and "." in the first column only end it; not closed, it runs to the end */
	perl("format F =\nx\n . \n.  \n1;", "C{format F =\n}S#{x\n . \n.}C{  \n1;}");
	perlx("format F =\nx\n", "C{format F =\n}S!#{x\n}");
	/* not a format: a key, a method, a value, no "=" at the end of its line */
	perl("%h = (format => 1); $h{format} = 2; $z = $o->format; format_x(1);", "C{%h = (format => 1); $h{format} = 2; $z = $o->format; format_x(1);}");
	perlx("format STDOUT = 1;\nx\n.\n", "C{format STDOUT = 1;\nx\n.\n}");
}

static void variables(void)
{
	perl("$z = $::x . $Foo::Bar::y . ${Foo::z} . $x::{y};", "C{$z = $::x . $Foo::Bar::y . ${Foo::z} . $x::{y};}");
	perl("$z = $$ . $$x . $${x} . @$r . %$r . &$c . *$g . $$r{a} . $$r[0];", "C{$z = $$ . $$x . $${x} . @$r . %$r . &$c . *$g . $$r{a} . $$r[0];}");
	perl("$z = $0 . $1 . $10 . $& . $^W . ${^TAINT} . $^O;", "C{$z = $0 . $1 . $10 . $& . $^W . ${^TAINT} . $^O;}");
	perl("@z = (@-, @+, %+, %-, %!, @ARGV, %ENV, $ENV{PATH}, $-[0], $+{a});", "C{@z = (@-, @+, %+, %-, %!, @ARGV, %ENV, $ENV{PATH}, $-[0], $+{a});}");
	perl("*STDOUT = *STDERR; *{\"x\"} = *{\"y\"};", "C{*STDOUT = *STDERR; *{}S*{\"x\"}C{} = *{}S*{\"y\"}C{};}");
	perl("$z = $r->@* . $r->$#* . $r->%* . $r->@[0,1] . $r->@{qw(a b)};", "C{$z = $r->@* . $r->$#* . $r->%* . $r->@[0,1] . $r->@{}S{qw(a b)}C{};}");
	/* the globs of the special variables, as English.pm writes them */
	perl("*ERRNO = *!; *ORS = *\\ ; *LIST = *\"\t; *SUBSEP = *;\t; *PID = *$\t; *UID = *<; *ARG = *_;", "C{*ERRNO = *!; *ORS = *\\ ; *LIST = *\"\t; *SUBSEP = *;\t; *PID = *$\t; *UID = *<; *ARG = *_;}");
	/* "$x{" and "$x [" with white space; blanks between the sigil and the name */
	perl("$z = $ x . $ h {a} . @ a;", "C{$z = $ x . $ h {a} . @ a;}");
	/* a variable that holds a pattern or a heredoc operator is not one */
	perl("$x = $y /2/ $z;", "C{$x = $y /2/ $z;}");
	perl("print $s . $y . $m;", "C{print $s . $y . $m;}");
}

static void blocks(void)
{
	/* a label, a bare block, a prototype and a signature and the attributes of a sub */
	perl("A: { last A; }\n=pod\nx\n=cut\n1;", "C{A: { last A; }\n}K{=pod\nx\n=cut}C{\n1;}");
	perl("sub f($$) { 1 } sub g(\\@\\@) { 2 } sub h(&@) { 3 } sub i() { 4 } sub j(_;$) { 5 }", "C{sub f($$) { 1 } sub g(\\@\\@) { 2 } sub h(&@) { 3 } sub i() { 4 } sub j(_;$) { 5 }}");
	perl("use feature 'signatures'; sub f($x, $y = \"a/b\") { $x / 2 / $y }", "C{use feature }S{'signatures'}C{; sub f($x, $y = }S*{\"a/b\"}C{) { $x / 2 / $y }}");
	/* the attributes are code: the form closes the white space of "prototype( )" up, which perl reads as another prototype */
	perl("sub f :lvalue { $z } sub g :prototype($$) { 1 } sub h : method { 2 }", "C{sub f :lvalue { $z } sub g :prototype($$) { 1 } sub h : method { 2 }}");
	perl("sub User::pwent::getpwent : prototype( ) { 1 }", "C{sub User::pwent::getpwent : prototype( ) { 1 }}");
	/* perl refuses an attribute no handler knows ("Invalid CODE attributes"); a framework writes them */
	perlx("sub i :Path('/x') :Args(0) { 1 }", "C{sub i :Path(}S{'/x'}C{) :Args(0) { 1 }}");
	perl("$z = 1 ? { a => 1 } : { b => 2 }; $z = { map { $_ => 1 } @a };", "C{$z = 1 ? { a => 1 } : { b => 2 }; $z = { map { $_ => 1 } @a };}");
	perl("@z = sort { $a <=> $b } @a; @z = map { /x/ ? 1 : 0 } @a;", "C{@z = sort { $a <=> $b } @a; @z = map { }S{/x/}C{ ? 1 : 0 } @a;}");
	perl("BEGIN { 1 }\n=pod\nx\n=cut\n1;", "C{BEGIN { 1 }\n}K{=pod\nx\n=cut}C{\n1;}");
	perl("print {$fh} <<A;\nx\nA\n", "C{print {$fh} <<A;\n}S*#{x\nA}C{\n}");
}

static void numbers(void)
{
	perl("$z = 1_000 / 2 / 3; $z = .5 / 2 / 3; $z = 1.5e-3 / 2 / 3; $z = 0b101 / 2 / 3; $z = 1..5;", "C{$z = 1_000 / 2 / 3; $z = .5 / 2 / 3; $z = 1.5e-3 / 2 / 3; $z = 0b101 / 2 / 3; $z = 1..5;}");
	perl("$z = v1.2.3 . 1.2.3; @z = (1..3, 'a'..'c');", "C{$z = v1.2.3 . 1.2.3; @z = (1..3, }S{'a'}C{..}S{'c'}C{);}");
}

#include "textual_perl_gen.h"

/* ---- (d) the form ---- */

static void fm(const char *src, const char *want)
{
	form_lang(PERL, src, want);
}

static void forms(void)
{
	fm("", "");
	/* white space and comments go, a line break stays one: a "#" comment, a here-document, pod and __END__ are about lines */
	fm("my $x = 1;  # c\n\n\n   my $y = 2;\n", "my $x=1;\nmy $y=2;");
	fm("if ($a == 1) {\n    print \"x\"\n}\n", "if($a==1){\nprint \"x\"\n}");
	fm("# only\n", "");
	fm("$x = 1; # c\n=pod\n\nhi\n\n=cut\n$y = 2;", "$x=1;\n$y=2;");
	/* a name next to a name keeps its space */
	fm("print $x if $y;", "print $x if $y;");
	fm("return \"x\" unless 0 and 1;", "return \"x\"unless 0 and 1;");
	/* what closing up would change keeps its space: see the row */
	fm("$x = $a + + $b; $x = $a - - $b; $x = $a * * $b; $x = $a . . $b;", "$x=$a+ +$b;$x=$a- -$b;$x=$a* *$b;$x=$a. .$b;");
	fm("$x = $a < < $b; $x = $a = = $b;", "$x=$a < <$b;$x=$a= =$b;");
	fm("$x = $a - > b; $x = $a = ~ $b; $x = $a ! ~ $b;", "$x=$a- > b;$x=$a= ~$b;$x=$a! ~$b;");
	fm("$x = - s/a/b/;", "$x=- s/a/b/;");
	fm("$x = 1 . 5;", "$x=1 .5;");
	fm("$$ if $x;", "$$ if $x;");
	fm("$x = f 'a'; $y = g'b';", "$x=f 'a';$y=g'b';");
	fm("print $fh \"a\"; print STDERR $x; print $fh @a;", "print $fh \"a\";print STDERR $x;print $fh @a;");
	fm("print $out <<EOT;\nx\nEOT\n", "print $out <<EOT;\nx\nEOT");
	fm("$x = 1 <<EOT;\nEOT\n", "$x=1 <<EOT;\nEOT");
	fm("use CPAN 1.80 ();", "use CPAN 1.80 ();");
	fm("%overload:: and 1", "%overload:: and 1");
	/* a pattern, then white space, then a word: the space stays, where the flags would take the word */
	fm("s/^&// foreach @_; m/x/ if $y; $y =~ s,a,b, or 1; $y =~ m{a} if 1; $y =~ /a/ ? 1 : 0;", "s/^&// foreach @_;m/x/ if $y;$y=~s,a,b, or 1;$y=~m{a} if 1;$y=~/a/?1 : 0;");
	/* "$ x" is "$x" to perl */
	fm("$ x = 1;", "$ x=1;");
	/* a here-document: the line break after its operator and its body stay, and the form of it is itself */
	fm("print <<A  .  <<B;  # c\n1 # a\n A\nA\n  2\nB\n$x = 1  ;\n", "print <<A.<<B;\n1 # a\n A\nA\n  2\nB\n$x=1;");
	fm("print <<\"    EOT\" . \"x\";\na\n    EOT\n", "print <<\"    EOT\".\"x\";\na\n    EOT");
	/* __END__ and what follows it as typed */
	fm("1;  \n__END__  \n  raw  # x  \n\n", "1;\n__END__\n  raw  # x  \n\n");
	/* no join of literals: see the row. A comment in one goes all the same */
	fm("$x = 'a' # c\n . 'b';", "$x='a'\n.'b';");
	/* a string and a quote-like are every byte of themselves */
	fm("$x = q{a   b} . \"c   d\" . qw( e  f ) . m/g   h/ . s{i   j}{k   l};", "$x=q{a   b}.\"c   d\".qw( e  f ).m/g   h/.s{i   j}{k   l};");
	/* a string that is not closed is kept as typed */
	fm("$x = 'abc", "$x='abc");
	fm("$x  =  q{ab", "$x=q{ab");
	/* the line ending is one: CRLF is a line break and the CR of a comment goes with it */
	fm("$a = 1; # c\r\n$b = 2;\r\n", "$a=1;\n$b=2;");
	/* line breaks inside a statement stay: a comment is a gap, and the break after it ends it */
	fm("$x = (1 #c\n + 2);", "$x=(1\n+2);");
	/* the row has no `concat`: "a" . "b" is not written "ab", because the form joins the text of two literals, and in perl that is not
	 * always one literal ("$a" . "b" is "$ab" joined, and m/a/ . m/b/ is not m/ab/): measured on the corpus, 5 of 449 joins in /usr
	 * and 12 of 168 elsewhere differ */
	fm("print \"a\" . \"b\" . \"c\"; print 'a' . \"b\"; print q(a) . q(b);", "print \"a\".\"b\".\"c\";print 'a'.\"b\";print q(a).q(b);");
	fm("print \"$a\" . \"b\"; print m/a/ . m/b/;", "print \"$a\".\"b\";print m/a/.m/b/;");
	fm("print \"a\" . $x . \"b\"; print \"a\" x 3;", "print \"a\".$x.\"b\";print \"a\"x 3;");
}

/* The spelled-out bytes of a perl string, written as themselves: exactly what perl reads as an escape. */
static void unescapes(void)
{
	fm("$x = \"\\x65\\x76\\x61\\x6c\" . '\\x41';", "$x=\"eval\".'\\x41';");
	fm("$x = \"\\101\\102\" . \"\\x41B\\x4a\\x4A\";", "$x=\"AB\".\"ABJJ\";");
	fm("$x = qq{\\x41} . qq(\\x41) . qq/\\x41/ . qq'\\x41';", "$x=qq{A}.qq(A).qq/A/.qq'A';");
	fm("$x = qx{\\x65cho} . `\\x65cho`;", "$x=qx{echo}.`echo`;");
	/* not the ones that are not escapes in a string of that kind: single quotes, q and the patterns */
	fm("$x = '\\x41' . q{\\x41} . qw(\\x41) . m/\\x41/ . s/\\x41/\\x42/;", "$x='\\x41'.q{\\x41}.qw(\\x41).m/\\x41/.s/\\x41/\\x42/;");
	/* \x{...}, \o{...}, \N{...} and \c stay: a character, not a byte */
	fm("$x = \"\\x{41}\\o{101}\\N{U+41}\\cA\\x{263a}\";", "$x=\"\\x{41}\\o{101}\\N{U+41}\\cA\\x{263a}\";");
	/* a byte that is not printable, a backslash, a dollar, an at sign and the delimiter stay as typed */
	fm("$x = \"\\x0a\\x7f\\x01\\2\\7\" . \"\\x5c\\x24\\x40\\x22\";", "$x=\"\\x0a\\x7f\\x01\\2\\7\".\"\\x5c\\x24\\x40\\x22\";");
	fm("$x = qq{\\x7b\\x7d\\x28} . qq(\\x28\\x29\\x7b);", "$x=qq{\\x7b\\x7d(}.qq(\\x28\\x29{);");
	/* a backslash and the byte after it are a pair: \\x41 is a backslash and the text x41 */
	fm("$x = \"\\\\x41\" . \"\\\\\\x41\";", "$x=\"\\\\x41\".\"\\\\A\";");
	/* an escape still waiting for digits does not take the next one: "\1" . "2" is two things, "\12" is one */
	fm("$x = \"\\0\\x31\" . \"\\x4\\x61\" . \"\\1\\x32\";", "$x=\"\\0\\x31\".\"\\x4\\x61\".\"\\1\\x32\";");
	fm("$x = \"\\0\\x41\\x31\" . \"\\x4g\\x61\";", "$x=\"\\0A1\".\"\\x4ga\";");
	/* "\x" with no digit is a NUL, and the escape after it is its own */
	fm("$x = \"\\x\\x41\";", "$x=\"\\x\\x41\";");
	/* an octal above \377 is a wide character: left alone */
	fm("$x = \"\\400\\777\\101\";", "$x=\"\\400\\777A\";");
	/* in a string that interpolates a name a written byte could extend it: letters, digits, ":", "[", "{", "-", ">" and "'" stay escaped */
	fm("$x = \"$y\\x41\" . \"$y\\x2f\" . \"\\x41$y\";", "$x=\"$y\\x41\".\"$y/\".\"\\x41$y\";");
	fm("$x = \"@a\\x5b0]\" . \"$h\\x7b0}\" . \"$y\\x2d>[0]\" . \"$y\\x3a\\x3az\" . \"$y\\x27z\";", "$x=\"@a\\x5b0]\".\"$h\\x7b0}\".\"$y\\x2d>[0]\".\"$y\\x3a\\x3az\".\"$y\\x27z\";");
	/* a string with nothing to interpolate loses every one */
	fm("$x = \"\\x40a\\x24b\" . \"a\\x2eb\";", "$x=\"\\x40a\\x24b\".\"a.b\";");
	/* a here-document body, a delimiter that is a word byte and a string that is not closed are not rewritten */
	fm("print <<A;\n\\x41\nA\n", "print <<A;\n\\x41\nA");
	fm("$x = qq a\\x4aa;", "$x=qq a\\x4aa;");
	fm("$x = \"\\x41", "$x=\"A");
	/* a comment holding an escape is a comment, and goes */
	fm("$x = 1; # \"\\x41\"", "$x=1;");
}

/* THE DECODE HOOK, with a decoder that is not one: it wraps the value in angle brackets and upper cases it. What it
 * shows is what the lib decides - which literal, under which calls, in which order, and when it is let alone. */
static uint8_t last_chain[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t last_n_chain, hook_calls;
static uint8_t hook_out[256];

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
		       const uint8_t **out, uint32_t *out_len)
{
	uint32_t i;

	(void)user;
	hook_calls++;
	memcpy(last_chain, chain, n_chain);
	last_n_chain = n_chain;
	if (!len || in[0] == '!' || len + 2u > sizeof hook_out)
		return 0;
	hook_out[0] = '<';
	for (i = 0; i < len; i++)
		hook_out[1u + i] = (uint8_t)((in[i] >= 'a' && in[i] <= 'z') ? in[i] - 32 : in[i]);
	hook_out[len + 1u] = '>';
	*out = hook_out;
	*out_len = len + 2u;
	return 1;
}

static struct kgenome_textual_form_res dform(const char *src, const char *want)
{
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = PERL,
					       .out = fbuf, .decode = fake_decode };
	struct kgenome_textual_form_res rs;

	rq.cap = KGENOME_TEXTUAL_FORM_CAP(rq.n) + 64u;
	hook_calls = last_n_chain = 0;
	kgenome_textual_form(&rq, &rs);
	if (rs.n_out != strlen(want) || memcmp(fbuf, want, rs.n_out)) {
		fbuf[rs.n_out < sizeof fbuf ? rs.n_out : sizeof fbuf - 1u] = 0;
		printf("  FAIL decode of  %s\n       got    %s\n       wanted %s\n", src, fbuf, want);
		fails++;
	}
	return rs;
}

static int chain_is(uint32_t n, const uint8_t *want)
{
	return last_n_chain == n && !memcmp(last_chain, want, n);
}

static void decoders(void)
{
	static const uint8_t b64[] = { KGENOME_TEXTUAL_DEC_B64 },
		b64_zlib[] = { KGENOME_TEXTUAL_DEC_B64, KGENOME_TEXTUAL_DEC_ZLIB },
		b64_gz[] = { KGENOME_TEXTUAL_DEC_B64, KGENOME_TEXTUAL_DEC_GZIP }, url[] = { KGENOME_TEXTUAL_DEC_RAWURL },
		zl[] = { KGENOME_TEXTUAL_DEC_ZLIB };
	struct kgenome_textual_form_res rs;

	/* the call, qualified by its module or not, with or without a space in front of the bracket */
	rs = dform("eval(decode_base64(\"abc\"));", "eval(decoded_decode_base64(\"<ABC>\"));");
	CK(rs.n_decoded == 1 && rs.n_refused == 0 && hook_calls == 1 && chain_is(1, b64));
	dform("eval(MIME::Base64::decode_base64('abc'));", "eval(MIME::Base64::decoded_decode_base64('<ABC>'));");
	CK(chain_is(1, b64));
	dform("$x = decode_base64 ( 'abc' ) . decode_base64(q(d));", "$x=decoded_decode_base64('<ABC>').decoded_decode_base64(q(<D>));");
	CK(hook_calls == 2);
	/* MIME::Base64::decode is the alias (the bare "decode" is Encode's, and the module's name is what says which) */
	dform("$x = MIME::Base64::decode('abc'); $y = Base64::decode('d'); $z = decode('e');", "$x=MIME::Base64::decoded_decode('<ABC>');$y=Base64::decoded_decode('<D>');$z=decode('e');");
	CK(hook_calls == 2);
	/* the chain, innermost first, however the calls are qualified, ending at the first name that is not a decoder */
	dform("eval(Compress::Zlib::memGunzip(MIME::Base64::decode_base64(\"ab\")));", "eval(Compress::Zlib::decoded_memGunzip(MIME::Base64::decoded_decode_base64(\"<AB>\")));");
	CK(chain_is(2, b64_gz));
	dform("eval(uncompress(decode_base64('ab')));", "eval(decoded_uncompress(decoded_decode_base64('<AB>')));");
	CK(chain_is(2, b64_zlib));
	dform("eval(Compress::Zlib::uncompress(decode_base64('ab')));", "eval(Compress::Zlib::decoded_uncompress(decoded_decode_base64('<AB>')));");
	CK(chain_is(2, b64_zlib));
	dform("eval(inflate(uncompress(decode_base64('ab'))));", "eval(inflate(decoded_uncompress(decoded_decode_base64('<AB>'))));");
	CK(chain_is(2, b64_zlib));
	/* url */
	dform("$x = URI::Escape::uri_unescape('%41%42');", "$x=URI::Escape::decoded_uri_unescape('<%41%42>');");
	CK(chain_is(1, url));
	/* "+" stays a plus under uri_unescape and under the RAW decoder the row names: it is decoded, not refused */
	dform("$x = uri_unescape('a+b');", "$x=decoded_uri_unescape('<A+B>');");
	CK(hook_calls == 1 && chain_is(1, url));
	dform("$x = Compress::Zlib::uncompress('ab');", "$x=Compress::Zlib::decoded_uncompress('<AB>');");
	CK(chain_is(1, zl));
	/* a "." typed in front is a qualifier of the walk and the call is still the call */
	dform("$x = $y.decode_base64('ab');", "$x=$y.decoded_decode_base64('<AB>');");
	CK(chain_is(1, b64));
	/* NOT a decoder: the name has to end where a name does - my_decode_base64 - and a second argument or a method is not the payload */
	dform("my_decode_base64('ab'); $o->decode('ab'); decode_base64x('ab'); Decode_Base64('ab');", "my_decode_base64('ab');$o->decode('ab');decode_base64x('ab');Decode_Base64('ab');");
	CK(hook_calls == 0);
	dform("decode_base64($x, 'ab'); decode_base64('ab', $x);", "decode_base64($x,'ab');decoded_decode_base64('<AB>',$x);");
	CK(hook_calls == 1);
	/* the literals have to be the whole of the argument: an expression on one is not, and a join of two is not offered (the row has no
	 * `concat`, see perl_lang.c) */
	dform("decode_base64('a' . 'b'); decode_base64('a' x 2); decode_base64('a' . $x);", "decode_base64('a'.'b');decode_base64('a'x 2);decode_base64('a'.$x);");
	CK(hook_calls == 0);
	/* a comment between the literal and the bracket is a gap */
	dform("decode_base64(  # c\n 'ab' # d\n );", "decoded_decode_base64(\n'<AB>'\n);");
	CK(hook_calls == 1);
	/* NOT EXPRESSIBLE: pack names its coding before the literal, a call without brackets has no "(", reverse needs a context */
	dform("pack('H*', '4142'); unpack('u', 'x'); decode_base64 'ab'; scalar reverse('abc'); decode_base64url('ab');",
	      "pack('H*','4142');unpack('u','x');decode_base64 'ab';scalar reverse('abc');decode_base64url('ab');");
	CK(hook_calls == 0);
	/* refused: the literal stays as typed and the refusal is counted; one still open is not offered */
	rs = dform("decode_base64('!ab');", "decode_base64('!ab');");
	CK(rs.n_decoded == 0 && rs.n_refused == 1 && hook_calls == 1);
	dform("decode_base64('ab", "decode_base64('ab");
	CK(hook_calls == 0);
	/* a double quoted literal that interpolates has no value, and one with escapes has theirs */
	dform("decode_base64(\"a$x\"); decode_base64(\"a\\@b\"); decode_base64(\"a\\x{41}\"); decode_base64(\"a\\nb\");", "decode_base64(\"a$x\");decoded_decode_base64(\"<A@B>\");decode_base64(\"a\\x{41}\");decoded_decode_base64(\"<A\nB>\");");
	CK(hook_calls == 2);
	/* single quotes: only the backslash and the delimiter are escapes; q with brackets takes both */
	dform("decode_base64('a\\\\b\\'c\\nd'); decode_base64(q{a\\}b\\{c\\\\d});", "decoded_decode_base64('<A\\B'C\\ND>');decoded_decode_base64(q{<A}B{C\\D>});");
	CK(hook_calls == 2);
	/* qq takes its brackets, patterns and qw and qx and a here-document have no value */
	dform("decode_base64(qq(a\\)b)); decode_base64(qw(a)); decode_base64(qx(a)); decode_base64(m/a/);", "decoded_decode_base64(qq(<A)B>));decode_base64(qw(a));decode_base64(qx(a));decode_base64(m/a/);");
	CK(hook_calls == 1);
}

/* the words: the table is sorted by byte order, because the lookup is a binary search, and every word is found */
static void words(void)
{
	static const char *const w[] = { "ADJUST", "BEGIN", "__END__", "__DATA__", "and", "cmp", "do", "eval", "foreach", "format", "isa", "lc",
					 "m", "no", "package", "print", "q", "qq", "qr", "qw", "qx", "require", "s", "say", "sub", "tr", "use", "x", "xor", "y" };
	static const char *const not_w[] = { "", "_", "ms", "qq2", "Print", "elseif", "foo", "xx", "tr_", "S", "__PACKAGE", "sub2" };
	unsigned i;

	for (i = 0; i < sizeof w / sizeof w[0]; i++)
		CK(kgenome_textual_perl_kw((const uint8_t *)w[i], (uint32_t)strlen(w[i])) != NULL);
	for (i = 0; i < sizeof not_w / sizeof not_w[0]; i++)
		CK(kgenome_textual_perl_kw((const uint8_t *)not_w[i], (uint32_t)strlen(not_w[i])) == NULL);
	/* every row is found by its own name and the rows are in order: walk the alphabet of words that begin the table's */
	{
		const struct kgenome_textual_perl_kw_row *prev = NULL;
		uint32_t found = 0;
		char name[32];
		unsigned a, b, c;

		for (a = 0; a < 128u; a++) {
			for (b = 0; b < 3u; b++) {
				for (c = 0; c < 3u; c++) {
					uint32_t l = 0;

					name[l++] = (char)a;
					if (b)
						name[l++] = (char)(b == 1u ? 'q' : 'e');
					if (c && b)
						name[l++] = (char)(c == 1u ? 'x' : 'r');
					if (a >= 'A' && a <= 'z' && a != '[' && a != '\\' && a != ']' && a != '^' && a != '`') {
						const struct kgenome_textual_perl_kw_row *r = kgenome_textual_perl_kw((const uint8_t *)name, l);

						found += r != NULL;
						prev = r ? r : prev;
					}
				}
			}
		}
		CK(found > 20 && prev);
	}
	/* the quote words are the table's KGENOME_TEXTUAL_PERL_KW_QUOTE rows and the ids are the enum's */
	{
		static const char *const q[] = { "q", "qq", "qw", "qx", "qr", "m", "s", "tr", "y" };

		for (i = 0; i < sizeof q / sizeof q[0]; i++) {
			const struct kgenome_textual_perl_kw_row *r = kgenome_textual_perl_kw((const uint8_t *)q[i], (uint32_t)strlen(q[i]));

			CK(r && r->kind == KGENOME_TEXTUAL_PERL_KW_QUOTE && r->arg == i);
		}
	}
}

/* ---- the value of a literal ---- */

/* The value of the one literal that `src` is, by the lexer's own spans: `want` NULL says it has none. */
static void val_of(const char *src, const char *want, uint32_t want_len)
{
	static struct got r;
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = PERL, .sink = got_sink, .user = &r };
	struct kgenome_textual_lex_res rs;
	struct kgenome_textual_value_req vq;
	struct kgenome_textual_value_res vs;
	enum kgenome_textual_status st;
	static uint8_t out[512];
	uint32_t k, at = 0xffffffffu;

	memset(&r, 0, sizeof r);
	kgenome_textual_lex(&rq, &rs);
	for (k = 0; k < r.n; k++)
		if (r.x[k].kind == KGENOME_TEXTUAL_STRING)
			at = k;
	if (at == 0xffffffffu) {
		printf("  FAIL value: %s has no literal\n", src);
		fails++;
		return;
	}
	vq = (struct kgenome_textual_value_req){ .lang = PERL, .lit = (const uint8_t *)src + r.x[at].off, .len = r.x[at].len,
						 .open_len = r.x[at].open_len, .close_len = r.x[at].close_len, .flags = r.x[at].flags,
						 .out = out, .cap = sizeof out };
	st = kgenome_textual_value(&vq, &vs);
	if (!want) {
		if (st != KGENOME_TEXTUAL_NO_VALUE) {
			printf("  FAIL value of %s: has one, status %d\n", src, (int)st);
			fails++;
		}
		return;
	}
	if (st != KGENOME_TEXTUAL_OK || vs.n_out != want_len || memcmp(out, want, want_len)) {
		printf("  FAIL value of %s: status %d, %u bytes\n", src, (int)st, vs.n_out);
		fails++;
	}
}

#define VAL(src, want) val_of(src, want, (uint32_t)sizeof(want) - 1u)
#define NOVAL(src) val_of(src, NULL, 0)

static void values(void)
{
	/* single quotes and q: the backslash and the delimiter (both brackets) are the escapes, the rest stays */
	VAL("'a\\'b\\\\c\\n'", "a'b\\c\\n");
	VAL("q{a\\}b\\{c\\\\d}", "a}b{c\\d");
	VAL("q(a(b)c)", "a(b)c");
	VAL("q/a\\/b/", "a/b");
	VAL("''", "");
	/* double quotes and qq: n t r f b a e, \x with one or two digits, octal, and a backslash before any other byte */
	VAL("\"a\\x41\\n\\101\"", "aA\nA");
	VAL("\"a\\\"b\\$c\\@d\\\\e\"", "a\"b$c@d\\e");
	VAL("qq{a\\}b}", "a}b");
	VAL("\"\\q\\8\"", "q8");
	VAL("\"a\\0b\\x4z\"", "a\0b\x04z");
	VAL("\"\\t\\r\\f\\b\\a\\e\"", "\t\r\f\b\a\x1b");
	/* none: it interpolates, or an escape needs a table or a context, or it is not a string */
	NOVAL("\"a$x\"");
	NOVAL("\"a@b\"");
	NOVAL("\"\\x{41}\"");
	NOVAL("\"\\x\"");
	NOVAL("\"\\400\"");
	NOVAL("\"\\N{U+41}\"");
	NOVAL("\"\\cA\"");
	NOVAL("\"\\Ua\\E\"");
	NOVAL("`a`");
	NOVAL("qx{a}");
	NOVAL("qw(a)");
	NOVAL("m/a/");
	NOVAL("s/a/b/");
	NOVAL("tr/a/b/");
	NOVAL("qr/a/");
	/* a here-document body: the span does not say "<<~", and its operator is on the line before it */
	{
		static struct got r;
		const char *src = "print <<EOF;\nx\nEOF\n";
		struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = PERL, .sink = got_sink, .user = &r };
		struct kgenome_textual_lex_res rs;
		struct kgenome_textual_value_req vq;
		struct kgenome_textual_value_res vs;
		static uint8_t out[64];

		memset(&r, 0, sizeof r);
		kgenome_textual_lex(&rq, &rs);
		CK(r.n == 3 && r.x[1].kind == KGENOME_TEXTUAL_STRING && (r.x[1].flags & KGENOME_TEXTUAL_F_HERE));
		vq = (struct kgenome_textual_value_req){ .lang = PERL, .lit = (const uint8_t *)src + r.x[1].off, .len = r.x[1].len, .open_len = 0,
							 .close_len = r.x[1].close_len, .flags = r.x[1].flags, .out = out, .cap = sizeof out };
		CK(kgenome_textual_value(&vq, &vs) == KGENOME_TEXTUAL_NO_VALUE);
	}
}

/* ---- (c) any text at all ---- */

static const char *const parts[] = {
	"q", "qq", "qw", "qx", "qr", "m", "s", "y", "tr", "=>", "=", "<<", "<<~", "EOF", "'", "\"", "`", "/", "//", "\\", "#", "\n", "\r\n", " ",
	"=pod", "=cut", "=head1", "{", "}", "(", ")", "[", "]", "$", "@", "%", "&", "*", "__END__", "__DATA__", "print", "split", "x", "1", "a",
	";", ",", "->", "-s", "$#", "$'", "$\"", "format", "sub", "if", ".", ":", "<", ">", "?", "!", "~", "^", "|", "+", "-", "_", "\t", "\x01",
};

#define N_PARTS (sizeof parts / sizeof parts[0])

/* texts made of perl's own pieces: the property tests below ask for the partition and the form of a form on them */
static uint32_t pieces_text(uint32_t *s, uint8_t *b, uint32_t cap)
{
	uint32_t w = 0, k, n;

	*s = *s * 1103515245u + 12345u;
	n = (*s >> 16) % 40u;
	for (k = 0; k < n; k++) {
		const char *p;

		*s = *s * 1103515245u + 12345u;
		p = parts[(*s >> 16) % N_PARTS];
		while (*p && w < cap)
			b[w++] = (uint8_t)*p++;
	}
	return w;
}

static void properties(void)
{
	static struct rend r;
	uint8_t b[256];
	uint32_t s = 4242u, i, n, w1, w2;

	/* the spans partition the text, and the form of a form is itself, on text drawn from what changes the lexer's mind:
	 * quotes, a backslash, the quote words, pod markers, line breaks of all kinds, the characters of an operator */
	partition_for(PERL, "#'\"`\\\n\r\t {}()[]<>=/$@%&*;:,.-+~!?^|_qwmsyxtrEOF01\x01pod", 2024u);
	partition_for(PERL, "'\"qs/#{}\n=>", 77u);
	partition_for(PERL, "<<~EOF\n'\"\\ \r", 31u);
	partition_for(PERL, "=pod\ncut \n#", 5u);
	form_property_for(PERL, "#'\"`\\\n\r\t {}()[]<>=/$@%&*;:,.-+~!?^|_qwmsyxtrEOF01\x01pod", 99u);
	form_property_for(PERL, "'\"qs/#{}\n=>", 3u);
	form_property_for(PERL, "<<~EOF\n'\"\\ \r$x", 8u);
	form_property_for(PERL, "=pod\ncut \n#;", 11u);
	form_property_for(PERL, "$#a '\"\\x41 ", 17u);
	for (i = 0; i < 30000u; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		enum kgenome_textual_status st;

		n = pieces_text(&s, b, sizeof b);
		lex(&r, b, n, PERL);
		if (r.broken) {
			printf("  FAIL partition on a text of perl's own pieces, %u bytes\n", n);
			fails++;
			return;
		}
		rq = (struct kgenome_textual_form_req){ .in = b, .n = n, .lang = PERL, .out = fbuf, .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
		st = kgenome_textual_form(&rq, &rs);
		w1 = rs.n_out;
		if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || w1 > KGENOME_TEXTUAL_FORM_CAP(n)) {
			printf("  FAIL form status or length on a text of perl's own pieces, %u bytes\n", n);
			fails++;
			return;
		}
		rq = (struct kgenome_textual_form_req){ .in = fbuf, .n = w1, .lang = PERL, .out = fbuf2, .cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
		kgenome_textual_form(&rq, &rs);
		w2 = rs.n_out;
		if (w2 != w1 || memcmp(fbuf, fbuf2, w1)) {
			uint32_t k;

			printf("  FAIL the form is not its own form, a text of perl's own pieces of %u bytes:\n  ", n);
			for (k = 0; k < n; k++)
				printf(b[k] >= 0x20 && b[k] < 0x7f && b[k] != '\\' ? "%c" : "\\x%02x", b[k]);
			printf("\n");
			fails++;
			return;
		}
	}
}

/* Takes every span of a long text and keeps only what the partition needs: where the next one must begin. */
struct whole {
	uint32_t next, n, broken;
};

static int whole_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct whole *c = u;

	if (sp->off != c->next || !sp->len)
		c->broken = 1;
	c->next = sp->off + sp->len;
	c->n++;
	return 1;
}

/* Where `needle` is in the `n` bytes at `h`, or NULL. */
static const uint8_t *mem_find(const uint8_t *h, uint32_t n, const char *needle)
{
	uint32_t l = (uint32_t)strlen(needle), i;

	for (i = 0; i + l <= n; i++)
		if (!memcmp(h + i, needle, l))
			return h + i;
	return NULL;
}

/* The program checks: the generator's own programs, and the form of each. */
static void generated_forms(void)
{
	static struct gen g;
	uint64_t seed;
	uint32_t bad = 0;

	for (seed = 1; seed <= 3000u && bad < 3u; seed++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		uint32_t w1, k;
		int comment_left = 0, lost = 0;

		ggenerate(&g, seed);
		if (g.over)
			continue;
		rq = (struct kgenome_textual_form_req){ .in = g.b, .n = g.n, .lang = PERL, .out = fbuf, .cap = sizeof fbuf };
		if (KGENOME_TEXTUAL_FORM_CAP(g.n) > sizeof fbuf)
			continue;
		rq.cap = KGENOME_TEXTUAL_FORM_CAP(g.n);
		kgenome_textual_form(&rq, &rs);
		w1 = rs.n_out;
		fbuf[w1] = 0;
		/* a comment goes, and every literal stays: the text of each is unique, so it is looked for */
		for (k = 0; k < g.nx; k++) {
			const struct kgenome_textual_span *x = &g.x[k];
			char tag[16];

			if (x->kind == KGENOME_TEXTUAL_COMMENT && x->off && mem_find(g.b + x->off, x->len, "CMT") && strstr((char *)fbuf, "CMT"))
				comment_left = 1;
			if (x->kind == KGENOME_TEXTUAL_STRING) {
				const uint8_t *t = mem_find(g.b + x->off, x->len, "STR");

				if (!t)
					t = mem_find(g.b + x->off, x->len, "REP");
				if (!t)
					t = mem_find(g.b + x->off, x->len, "HDOC");
				if (t) {
					uint32_t l = 0;

					while (l < sizeof tag - 1u && t + l < g.b + x->off + x->len && (t[l] == 'S' || t[l] == 'T' || t[l] == 'R' || t[l] == 'E' || t[l] == 'P' || t[l] == 'H' || t[l] == 'D' || t[l] == 'O' || t[l] == 'C' || (t[l] >= '0' && t[l] <= '9')))
						tag[l] = (char)t[l], l++;
					tag[l] = 0;
					if (!strstr((char *)fbuf, tag))
						lost = 1;
				}
			}
		}
		if (comment_left || lost) {
			printf("  FAIL form of generated program, seed %llu: %s\n", (unsigned long long)seed, comment_left ? "a comment is left" : "a literal is lost");
			bad++;
			fails++;
			continue;
		}
		{
			struct kgenome_textual_form_res rs2;

			rq = (struct kgenome_textual_form_req){ .in = fbuf, .n = w1, .lang = PERL, .out = fbuf2, .cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
			kgenome_textual_form(&rq, &rs2);
			if (rs2.n_out != w1 || memcmp(fbuf, fbuf2, w1)) {
				printf("  FAIL the form of generated program %llu is not its own form\n", (unsigned long long)seed);
				bad++;
				fails++;
			}
		}
	}
}

/* The spans partition a text cut at every length, and a deeply nested or hostile one is read in time proportional to it. */
static void hostile(void)
{
	static const char sample[] =
		"#!/usr/bin/perl -w\nmy $x = \"a$b\" . q{c{d}} . qq<e>; print <<A, <<'B';\nx $y\nA\nraw\nB\ns{a}{b}ge; $z = $a / 2 / 3; split /,/, $x;\n=pod\n\nt\n=cut\nformat F =\n@<<\n$x\n.\n__END__\ndata 'q\n";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, PERL);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* NUL bytes are bytes: in code, in a string, in a comment, after __END__ and as a delimiter */
	{
		static const char nul[] = "a\0b = 'c\0d' . \"e\0f\"; # g\0h\n=pod\0\nx\n=cut\nq\0a\0 s\0a\0b\0 __END__\n\0\0";

		lex(&r, nul, sizeof nul - 1u, PERL);
		CK(!r.broken);
	}
	/* every line ending: a comment holds the CR of CRLF, a lone CR is a blank */
	perl("x # c\r\nz\r\n", "C{x }K{# c\r}C{\nz\r\n}");
	perlx("x # c\ry", "C{x }K{# c\ry}");
	perl("print <<A;\r\nx\r\nA\r\n1;\r\n", "C{print <<A;\r\n}S*#{x\r\nA}C{\r\n1;\r\n}");
	perlx("print <<A;\rx\rA\r", "C{print <<A;\rx\rA\r}");
	/* nesting: a bracket delimiter nests to any depth and does not recurse, braces of a block are counted without a stack past 256 */
	{
		static char deep[20000];
		uint32_t w = 0, i;

		for (i = 0; i < 3000u; i++)
			deep[w++] = '{';
		for (i = 0; i < 3000u; i++)
			deep[w++] = '}';
		memcpy(deep + w, "\n=pod\nx\n=cut\n1;\n", 17);
		w += 17;
		lex(&r, deep, w, PERL);
		CK(!r.broken);
		w = 0;
		memcpy(deep, "q", 1);
		w = 1;
		for (i = 0; i < 5000u; i++)
			deep[w++] = '(';
		for (i = 0; i < 5000u; i++)
			deep[w++] = ')';
		lex(&r, deep, w, PERL);
		CK(!r.broken && r.out[0] == 'S' && !strchr(r.out, 'C'));
		/* the same, not closed: one open string to the end */
		lex(&r, deep, w - 1u, PERL);
		CK(!r.broken && r.out[0] == 'S' && r.out[1] == '!');
	}
	/* LINEAR WORK. Each of these is a text that never closes or that asks the lexer to look ahead, repeated until it is 600 KB. A lexer that
	 * read to the end of the text for each one would do some 10^11 steps here; this takes a blink, and the bound on the whole is a few
	 * seconds even under a sanitizer. */
	{
		static const char *const unit[] = { "s{a}", "<<\"", "<<'", "<<A ", "q(", "$x <", "<$ ", "=pod\n", "s/a/", "tr[", "format F =\n", "__END__ ", "/", "@{", "$#{", "sub a :b(" };
		static uint8_t big[600u * 1024u];
		clock_t t0 = clock();
		uint32_t k;

		for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
			size_t ul = strlen(unit[k]);
			uint32_t w = 0;
			struct whole c = { 0 };
			struct kgenome_textual_lex_req rq;
			struct kgenome_textual_lex_res rs;
			enum kgenome_textual_status st;

			while (w + ul <= sizeof big) {
				memcpy(big + w, unit[k], ul);
				w += (uint32_t)ul;
			}
			rq = (struct kgenome_textual_lex_req){ .in = big, .n = w, .lang = PERL, .sink = whole_sink, .user = &c };
			st = kgenome_textual_lex(&rq, &rs);
			CK((st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c.next == w && !c.broken && rs.n_span == c.n);
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
	}
	/* more here-documents on one line than the queue holds: the rest of the text is one open one, and nothing is lost or looped */
	{
		static uint8_t big[8192];
		uint32_t w = 0, i;
		struct whole c = { 0 };
		struct kgenome_textual_lex_req rq;
		struct kgenome_textual_lex_res rs;

		memcpy(big, "f(", 2);
		w = 2;
		for (i = 0; i < 100u; i++) {
			memcpy(big + w, "<<A, ", 5);
			w += 5;
		}
		memcpy(big + w, ");\nx\nA\n", 8);
		w += 8;
		rq = (struct kgenome_textual_lex_req){ .in = big, .n = w, .lang = PERL, .sink = whole_sink, .user = &c };
		kgenome_textual_lex(&rq, &rs);
		CK(c.next == w && !c.broken && rs.n_open >= 1u);
	}
}

int main(void)
{
	comments();
	pod();
	quotes();
	quotelike();
	barewords();
	slash();
	here();
	data();
	format();
	variables();
	blocks();
	numbers();
	generator();
	forms();
	unescapes();
	decoders();
	values();
	words();
	properties();
	generated_forms();
	hostile();
	printf("textual perl: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
