/*
 * genome / api_textual - the php lexer of the textual part, through <kgenome.h> alone, linked
 * against libkgenome.a and nothing else.
 *
 * WHAT IS ASSERTED. A text is rendered as its spans, kind letter and the bytes in braces:
 *
 *     M markup  T tag  C code  S string  K comment
 *     S* may interpolate   S! not closed   S# heredoc or nowdoc (flags in that order)
 *
 * so a case is the input and the one line it must come out as, and a wrong boundary is a line
 * that differs rather than a count. The cases are php's own rules, each with the neighbour it
 * could be confused for: "<?xml" is markup and "<?=" is not; "<<<" with no label is code;
 * "?>" ends a line comment and does not end a block comment; a "}" inside a string inside
 * "{$...}" does not close the interpolation; a heredoc's closer is a LINE.
 *
 * THE FORM is checked the same way, by known answer: the input and the one text it must become.
 * What each case pins is a decision - a comment is a gap and not nothing (two names with
 * a comment between them stay two names), a pair of brackets is not a token ("f($a) )" is "f($a))"), a string is never touched,
 * a trailing comment goes, a lone brace joins the line above even when a comment follows it,
 * an island with no code in it goes whole - and the properties that make it a form at all: the
 * form of a form is itself, and the output is never longer than KGENOME_TEXTUAL_FORM_CAP.
 *
 * AND THE ONE THING TRUE OF ANY INPUT: the spans partition it - no gap, no overlap, in order,
 * each non-empty - checked on random byte strings drawn from the characters that mean something
 * and on a sample cut at every length.
 *
 * The corpus the lexer was written on has no heredoc, no __halt_compiler and no attribute, so
 * those rules are covered here and nowhere else.
 */

#include "textual_check.h"

static void expect(const char *src, const char *want)
{
	expect_lang(KGENOME_TEXTUAL_LANG_PHP, src, want);
}

/* posix shell */
static void sh(const char *src, const char *want)
{
	expect_lang(KGENOME_TEXTUAL_LANG_SH, src, want);
}

static void tags(void)
{
	expect("", "");
	expect("<b>x</b>", "M{<b>x</b>}");
	expect("<b>x</b><?php echo 1; ?>tail", "M{<b>x</b>}T{<?php }C{echo 1; }T{?>}M{tail}");
	/* "?>" takes one line break after it, as php does, and not two */
	expect("<?php a ?>\nrest", "T{<?php }C{a }T{?>\n}M{rest}");
	expect("<?php a ?>\r\n\nrest", "T{<?php }C{a }T{?>\r\n}M{\nrest}");
	expect("<?php", "T{<?php}");
	expect("<?PHP x", "T{<?PHP }C{x}");
	/* "<?php" needs white space after it: "<?phpx" is not a tag */
	expect("<?phpx", "M{<?phpx}");
	expect("<?xml version=\"1.0\"?>", "M{<?xml version=\"1.0\"?>}");
	expect("<?= $a ?>", "T{<?=}C{ $a }T{?>}");
	expect("<? echo 1;", "T{<? }C{echo 1;}");
	/* several islands */
	expect("a<?php b ?>c<?php d ?>e", "M{a}T{<?php }C{b }T{?>}M{c}T{<?php }C{d }T{?>}M{e}");
	/* a lone "<" and "<?" at the very end are markup */
	expect("a < b <?", "M{a < b <?}");
}

static void comments(void)
{
	expect("<?php // c ?>x", "T{<?php }K{// c }T{?>}M{x}");
	expect("<?php # h\nb", "T{<?php }K{# h}C{\nb}");
	expect("<?php // c\r\nb", "T{<?php }K{// c}C{\r\nb}");
	expect("<?php /* a */ b", "T{<?php }K{/* a */}C{ b}");
	/* "?>" does not end a block comment */
	expect("<?php /* ?> */ b", "T{<?php }K{/* ?> */}C{ b}");
	/* slash star slash is not a whole comment */
	expect("<?php /*/ x */ b", "T{<?php }K{/*/ x */}C{ b}");
	expect("<?php /* x", "T{<?php }K!{/* x}");
	/* "#[" opens an attribute, which is code */
	expect("<?php #[Attr]\nb", "T{<?php }C{#[Attr]\nb}");
	/* a comment marker inside a string is the string's */
	expect("<?php 'a // b'", "T{<?php }S{'a // b'}");
}

static void strings(void)
{
	expect("<?php 'a\\'b' c", "T{<?php }S{'a\\'b'}C{ c}");
	expect("<?php 'a\\\\' c", "T{<?php }S{'a\\\\'}C{ c}");
	expect("<?php \"a\\\"b\" c", "T{<?php }S*{\"a\\\"b\"}C{ c}");
	expect("<?php 'x", "T{<?php }S!{'x}");
	expect("<?php \"x", "T{<?php }S*!{\"x}");
	/* a trailing backslash does not run off the end */
	expect("<?php 'x\\", "T{<?php }S!{'x\\}");
	expect("<?php `ls -l` x", "T{<?php }S*{`ls -l`}C{ x}");
	/* interpolation is skipped as a unit: a quote or a brace inside it ends nothing */
	expect("<?php \"a{$b[\"k\"]}c\" x", "T{<?php }S*{\"a{$b[\"k\"]}c\"}C{ x}");
	expect("<?php \"a{$b['}']}c\" x", "T{<?php }S*{\"a{$b['}']}c\"}C{ x}");
	expect("<?php \"a${b}c\" x", "T{<?php }S*{\"a${b}c\"}C{ x}");
	expect("<?php \"a{$b\" x", "T{<?php }S*!{\"a{$b\" x}");
	/* "{" not followed by "$" is a plain byte */
	expect("<?php \"a{b}\" x", "T{<?php }S*{\"a{b}\"}C{ x}");
	/* "?>" inside a string is not a tag */
	expect("<?php 'a ?> b' c", "T{<?php }S{'a ?> b'}C{ c}");
}

static void heredocs(void)
{
	expect("<?php $a = <<<EOT\nline $x\nEOT;\nb", "T{<?php }C{$a = }S*#{<<<EOT\nline $x\nEOT}C{;\nb}");
	expect("<?php <<<\"EOT\"\nx\nEOT\n", "T{<?php }S*#{<<<\"EOT\"\nx\nEOT}C{\n}");
	/* a nowdoc does not interpolate */
	expect("<?php <<<'EOT'\nx $y\nEOT;", "T{<?php }S#{<<<'EOT'\nx $y\nEOT}C{;}");
	/* since 7.3 the closer may be indented */
	expect("<?php <<<EOT\n  x\n  EOT;", "T{<?php }S*#{<<<EOT\n  x\n  EOT}C{;}");
	/* a line that only STARTS with the label is not the closer */
	expect("<?php <<<EOT\nEOTX\nEOT;", "T{<?php }S*#{<<<EOT\nEOTX\nEOT}C{;}");
	expect("<?php <<<EOT\nxEOT\nEOT;", "T{<?php }S*#{<<<EOT\nxEOT\nEOT}C{;}");
	/* an empty body, and CRLF */
	expect("<?php <<<E\nE;", "T{<?php }S*#{<<<E\nE}C{;}");
	expect("<?php <<<E\r\nx\r\nE;", "T{<?php }S*#{<<<E\r\nx\r\nE}C{;}");
	/* a quote and a "?>" inside are text */
	expect("<?php <<<E\n' ?> \"\nE;", "T{<?php }S*#{<<<E\n' ?> \"\nE}C{;}");
	expect("<?php <<<E\nx", "T{<?php }S*!#{<<<E\nx}");
	/* not a heredoc: a shift, a banner, no label, no line break */
	expect("<?php $a <<< 2", "T{<?php }C{$a <<< 2}");
	expect("<?php $a <<<<<<< b", "T{<?php }C{$a <<<<<<< b}");
	expect("<?php $a << 2", "T{<?php }C{$a << 2}");
	expect("<?php <<<EOT", "T{<?php }C{<<<EOT}");
	/* the quote after "<<<" opens a label that never closes, so what is left is a string, open */
	expect("<?php <<<'EOT", "T{<?php }C{<<<}S!{'EOT}");
}

static void halt(void)
{
	expect("<?php a(); __halt_compiler(); <?php ' \" junk", "T{<?php }C{a(); __halt_compiler();}M{ <?php ' \" junk}");
	expect("<?php __HALT_COMPILER ( ) ;x", "T{<?php }C{__HALT_COMPILER ( ) ;}M{x}");
	expect("<?php __halt_compiler() ?>data<?php x", "T{<?php }C{__halt_compiler() }T{?>}M{data<?php x}");
	/* a variable of that name, or a call with an argument, is not the marker */
	expect("<?php $__halt_compiler(); 'x'", "T{<?php }C{$__halt_compiler(); }S{'x'}");
	expect("<?php __halt_compiler(1); 'x'", "T{<?php }C{__halt_compiler(1); }S{'x'}");
	expect("<?php __halt_compilerx(); 'x'", "T{<?php }C{__halt_compilerx(); }S{'x'}");
}

struct stopper {
	unsigned seen, stop_at;
};

/* Takes spans until the stop_at-th, which it refuses. */
static int stop_sink(void *u, const struct kgenome_textual_span *s)
{
	struct stopper *c = u;

	(void)s;
	return ++c->seen < c->stop_at;
}

static void sh_lexer(void)
{
	sh("", "");
	/* the line that names the interpreter is the language's, not a comment */
	sh("#!/bin/sh\necho hi\n", "T{#!/bin/sh}C{\necho hi\n}");
	sh("# only a comment\n", "K{# only a comment}C{\n}");
	/* a "#" is a comment where a word begins, and nowhere else */
	sh("echo a # c\n", "C{echo a }K{# c}C{\n}");
	sh("echo a#b", "C{echo a#b}");
	sh("echo $# x", "C{echo $# x}");
	sh("a;#c", "C{a;}K{#c}");
	sh("a|#c\nb", "C{a|}K{#c}C{\nb}");
	sh("a\\ #b", "C{a\\ #b}");
	sh("echo ${#v}", "C{echo ${#v}}");
	sh("a \\\n# c", "C{a \\\n}K{# c}");
	/* a line that begins with "#" is a comment even after a continuation, which the shell would call a word */
	sh("a\\\n# c", "C{a\\\n}K{# c}");
	/* single quotes hold everything, a backslash included */
	sh("echo 'a b'", "C{echo }S{'a b'}");
	sh("echo 'a\\' b", "C{echo }S{'a\\'}C{ b}");
	sh("echo 'a # \"b'", "C{echo }S{'a # \"b'}");
	sh("echo 'a", "C{echo }S!{'a}");
	/* double quotes: a backslash, and expansions that carry quotes of their own */
	sh("echo \"a b\" c", "C{echo }S*{\"a b\"}C{ c}");
	sh("echo \"a\\\"b\" c", "C{echo }S*{\"a\\\"b\"}C{ c}");
	sh("echo \"a $(echo \"b\") c\" d", "C{echo }S*{\"a $(echo \"b\") c\"}C{ d}");
	sh("echo \"${x:-\"y\"}\" d", "C{echo }S*{\"${x:-\"y\"}\"}C{ d}");
	sh("echo \"`echo \"x\"`\" d", "C{echo }S*{\"`echo \"x\"`\"}C{ d}");
	sh("echo \"$(echo ')')\" d", "C{echo }S*{\"$(echo ')')\"}C{ d}");
	sh("echo \"a", "C{echo }S*!{\"a}");
	sh("echo \"$(echo \"a", "C{echo }S*!{\"$(echo \"a}");
	/* $'...' has escapes, $"..." is a double quoted string, a backquote is a command */
	sh("echo $'a\\'b' c", "C{echo }S{$'a\\'b'}C{ c}");
	sh("echo $\"x\" c", "C{echo }S*{$\"x\"}C{ c}");
	sh("x=`echo \"a\"` y", "C{x=}S*{`echo \"a\"`}C{ y}");
	/* a quote after a backslash is not a quote; a substitution at the top level is code */
	sh("echo \\' x", "C{echo \\' x}");
	sh("echo $(echo \"a b\") x", "C{echo $(echo }S*{\"a b\"}C{) x}");
	sh("echo $(echo a # c\n) x", "C{echo $(echo a }K{# c}C{\n) x}");
	/* a here-document: the body is the lines after the operator's, through the delimiter's */
	sh("cat <<EOF\nhello $x\nEOF\necho done\n", "C{cat <<EOF\n}S*#{hello $x\nEOF}C{\necho done\n}");
	sh("cat <<'EOF'\n$x\nEOF\n", "C{cat <<'EOF'\n}S#{$x\nEOF}C{\n}");
	sh("cat <<\"EOF\"\n$x\nEOF\n", "C{cat <<\"EOF\"\n}S#{$x\nEOF}C{\n}");
	sh("cat <<\\EOF\n$x\nEOF\n", "C{cat <<\\EOF\n}S#{$x\nEOF}C{\n}");
	sh("cat <<-EOF\n\tx\n\tEOF\n", "C{cat <<-EOF\n}S*#{\tx\n\tEOF}C{\n}");
	sh("cat <<EOF | sh\nx # not\n'q\nEOF\nz", "C{cat <<EOF | sh\n}S*#{x # not\n'q\nEOF}C{\nz}");
	sh("cat <<EOF\nEOF\n", "C{cat <<EOF\n}S*#{EOF}C{\n}");
	sh("cat <<EOF\r\nx\r\nEOF\r\ny", "C{cat <<EOF\r\n}S*#{x\r\nEOF\r}C{\ny}");
	/* a line that only contains the delimiter is the end; one that merely starts with it, or is indented
	 * without "-", is not */
	sh("cat <<EOF\nEOFX\n EOF\nEOF\n", "C{cat <<EOF\n}S*#{EOFX\n EOF\nEOF}C{\n}");
	sh("cat <<EOF\nabc", "C{cat <<EOF\n}S*!#{abc}");
	sh("cat <<A <<B\na\nA\nb\nB\nx", "C{cat <<A <<B\n}S*#{a\nA}C{\n}S*#{b\nB}C{\nx}");
	sh("cat <<A\n", "C{cat <<A\n}");
	/* not a here-document: a here-string, arithmetic, a missing delimiter */
	sh("cat <<<word\nx", "C{cat <<<word\nx}");
	sh("echo $((1<<n))\nx", "C{echo $((1<<n))\nx}");
	sh("(( a << b ))\nx", "C{(( a << b ))\nx}");
	sh("a <<\n", "C{a <<\n}");
	sh("a << 'x\ny", "C{a << }S!{'x\ny}");
}

static void status(void)
{
	static struct rend r;
	enum kgenome_textual_status st;
	struct kgenome_textual_lex_req rq;
	struct kgenome_textual_lex_res rs;
	const char src[] = "<?php 'a' . 'b' . 'c';";
	unsigned k;

	st = lex(&r, "<?php 'a'", 9, KGENOME_TEXTUAL_LANG_PHP);
	CK(st == KGENOME_TEXTUAL_OK);
	st = lex(&r, "<?php 'a", 8, KGENOME_TEXTUAL_LANG_PHP);
	CK(st == KGENOME_TEXTUAL_OPEN);
	st = lex(&r, "abc", 3, KGENOME_TEXTUAL_LANG_NONE);
	CK(st == KGENOME_TEXTUAL_NO_LANG && r.out[0] == 0);
	st = lex(&r, "abc", 3, KGENOME_TEXTUAL_LANG_COUNT);
	CK(st == KGENOME_TEXTUAL_NO_LANG);
	st = lex(&r, "abc", 3, 0xffffffffu);
	CK(st == KGENOME_TEXTUAL_NO_LANG);

	/* the counts in the result are the spans delivered and the ones left open */
	memset(&r, 0, sizeof r);
	r.in = (const uint8_t *)src;
	r.n = sizeof src - 1u;
	rq = (struct kgenome_textual_lex_req){ .in = (const uint8_t *)src, .n = sizeof src - 1u,
					       .lang = KGENOME_TEXTUAL_LANG_PHP, .sink = sink, .user = &r };
	st = kgenome_textual_lex(&rq, &rs);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_span == 7u && rs.n_open == 0u);
	memset(&r, 0, sizeof r);
	r.in = (const uint8_t *)"<?php 'a' 'b";
	r.n = 12;
	rq = (struct kgenome_textual_lex_req){ .in = r.in, .n = 12, .lang = KGENOME_TEXTUAL_LANG_PHP,
					       .sink = sink, .user = &r };
	st = kgenome_textual_lex(&rq, &rs);
	CK(st == KGENOME_TEXTUAL_OPEN && rs.n_open == 1u);

	/* a sink that stops the walk is a status, and what came before it was delivered */
	for (k = 1; k < 4; k++) {
		struct stopper c = { 0, k };

		rq = (struct kgenome_textual_lex_req){ .in = (const uint8_t *)src, .n = sizeof src - 1u,
						       .lang = KGENOME_TEXTUAL_LANG_PHP, .sink = stop_sink, .user = &c };
		st = kgenome_textual_lex(&rq, &rs);
		CK(st == KGENOME_TEXTUAL_REFUSED && c.seen == k);
	}
}

static void form(const char *src, const char *want)
{
	uint32_t n;
	enum kgenome_textual_status st = form_of(src, (uint32_t)strlen(src), fbuf, sizeof fbuf, &n);

	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || n != strlen(want) ||
	    memcmp(fbuf, want, n)) {
		fbuf[n < sizeof fbuf ? n : sizeof fbuf - 1u] = 0;
		printf("  FAIL form of  %s\n       got    %s\n       wanted %s\n", src, fbuf, want);
		fails++;
	}
}

static void sh_forms(void)
{
	/* white space is syntax: one space where there was any, nowhere else; a trailing comment goes */
	form_lang(KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\n\n  if [ -f x ]; then\n    echo   hi   # say\n  fi\n",
		  "#!/bin/sh\nif [ -f x ]; then\necho hi\nfi");
	form_lang(KGENOME_TEXTUAL_LANG_SH, "ls  -la\nls-la\na | b\na|b", "ls -la\nls-la\na | b\na|b");
	/* a string and a here-document are not touched, and a hex escape in a sh string is not a byte */
	form_lang(KGENOME_TEXTUAL_LANG_SH, "echo  \"a   b\"   'c   d'  \"\\x41\"", "echo \"a   b\" 'c   d' \"\\x41\"");
	form_lang(KGENOME_TEXTUAL_LANG_SH, "cat <<EOF\n  x   y\nEOF\necho  done", "cat <<EOF\n  x   y\nEOF\necho done");
	form_lang(KGENOME_TEXTUAL_LANG_SH, "cat <<'EOF' >  f\n  # x\nEOF\n", "cat <<'EOF' > f\n  # x\nEOF");
	/* the interpreter line stays, a script with nothing else is that line */
	form_lang(KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\n# c\n", "#!/bin/sh");
	form_lang(KGENOME_TEXTUAL_LANG_SH, "# c\n  \n", "");
	/* line continuations stay: the break is part of the command, and the white space after it is the gap
	 * between two words - "{\<newline>  return" is not "{return" */
	form_lang(KGENOME_TEXTUAL_LANG_SH, "a  \\\n   b", "a \\\n b");
	form_lang(KGENOME_TEXTUAL_LANG_SH, "a \\\nb", "a \\\nb");
	form_lang(KGENOME_TEXTUAL_LANG_SH, "x || {\\\n\t\treturn 1\n}", "x || {\\\n return 1\n}");
}

static void forms(void)
{
	form("", "");
	form("<b>x</b>", "<b>x</b>");
	/* indentation, blank lines, a comment, spaces inside the brackets, Allman braces */
	form("<?php\n    // c\n\n    if ( isset( $a ) )\n    {\n        eval( b( $a ) );   /* r */\n    }\n?>\n<p>x</p>",
	     "<?php\nif(isset($a)){\neval(b($a));\n}\n?>\n<p>x</p>");
	/* the same program typed as K&R and with CRLF is the same text */
	form("<?php\r\nif ($a) {\r\n  b();\r\n}\r\n?>\r\nx", "<?php\nif($a){\nb();\n}\n?>\nx");
	/* a space is kept where two names would become one, and nowhere else */
	form("<?php echo $a ;", "<?php echo($a);");
	form("<?php return  $a;", "<?php return$a;");
	form("<?php new  Foo ( ) ;", "<?php new Foo();");
	form("<?php $a = 1 + +2 ; $b = 1 - -2 ; $c = $a . .5 ;", "<?php $a=1+ +2;$b=1- -2;$c=$a. .5;");
	form("<?php $a = $b ? $c : $d ;", "<?php $a=$b?$c:$d;");
	/* a pair of brackets, braces, commas or semicolons is not one token */
	form("<?php f( $a ) ) ; g( [ [ 1 ] ] ) ; ; ", "<?php f($a));g([[1]]);;");
	/* a comment is a gap: it separates two names and closes up around an operator */
	form("<?php a/* c */b", "<?php a b");
	form("<?php a/* c */+b", "<?php a+b");
	form("<?php $a /* c */ + 1", "<?php $a+1");
	form("<?php $a=1; // c\n$b=2;", "<?php $a=1;\n$b=2;");
	form("<?php $a=1; # c\n$b=2;", "<?php $a=1;\n$b=2;");
	/* a comment that is not closed is kept: what it holds is not known to be a comment */
	form("<?php $a; /* x", "<?php $a;/* x");
	/* a string is every byte of itself */
	form("<?php $a  =  'x   y\n  z' ;", "<?php $a='x   y\n  z';");
	form("<?php $a = \"x // y /* z */\" ;", "<?php $a='x // y /* z */';");
	form("<?php echo 'a' ;", "<?php echo('a');");
	form("<?php $a = 'x", "<?php $a='x");
	/* a double quoted string is written with its bytes as themselves where that says the same: a hex
	 * or octal escape of a printable byte is the byte, and a byte the string treats as something
	 * else, or that is not printable, stays an escape. Single quotes have no escapes. */
	form("<?php $a = \"\\x53\\x43\\x52\\x49\\x50\\x54\";", "<?php $a='SCRIPT';");
	form("<?php $a = \"\\101\\102\\x4a\\x4A\";", "<?php $a='ABJJ';");
	form("<?php $a = \"\\x41B\\x4\\x0\\x7f\\x22\\x5c\\x24\\x7b\";", "<?php $a=\"AB\\x4\\x0\\x7f\\x22\\x5c\\x24\\x7b\";");
	form("<?php $a = '\\x41\\101';", "<?php $a='\\x41\\101';");
	form("<?php $a = \"\\\\x41 \\n \\x4g \\xzz\";", "<?php $a=\"\\\\x41 \\n \\x4g \\xzz\";");
	/* a heredoc is one string, its body and its closer's indent untouched */
	form("<?php $a = <<<E\n  x \n  E;\n$b = 1;", "<?php $a= <<<E\n  x \n  E;\n$b=1;");
	/* a brace alone on its line joins the one above, a comment after the line above or after it
	 * notwithstanding, and a brace with something on its line does not */
	form("<?php\nif($a) // x\n{\n$b;\n}", "<?php\nif($a){\n$b;\n}");
	form("<?php\nif($a)\n{ // x\n$b;\n}", "<?php\nif($a){\n$b;\n}");
	form("<?php\nif($a)\n{ $b;\n}", "<?php\nif($a)\n{$b;\n}");
	form("<?php\n{\n$b;\n}", "<?php\n{\n$b;\n}");
	/* an island with no code goes whole, its tags too */
	form("a<?php // c\n?>b", "ab");
	/* the line break after "?>" is the tag's, so it goes with an empty island */
	form("a<?php\n\n?>\nb<?= $x ?>c", "ab<?=$x\n?>c");
	form("<?php", "");
	form("<?php // c", "");
	/* the line break in front of a closing tag, once */
	form("<?php a();?>x", "<?php a();\n?>x");
	form("<?php a();\n?>x", "<?php a();\n?>x");
	/* markup is markup: its spacing, its comment-like text and its line endings stay */
	form("<p>  a // b  </p>\r\n<?php a(); ?>  \r\n  z", "<p>  a // b  </p>\r\n<?php a();\n?>  \r\n  z");
	/* __halt_compiler: what follows is data and is left exactly as it is */
	form("<?php a ( ) ; __halt_compiler ( ) ;  x  y\n", "<?php a();__halt_compiler();  x  y\n");
}

/*
 * THE DECODE HOOK, with a decoder that is not one: it wraps the value in angle brackets and upper
 * cases it, and refuses a value that begins with "!". What it shows is what the lib decides - which
 * literal, under which calls, in which order, and when it is let alone - not what any algorithm does.
 */
static uint8_t last_chain[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t last_n_chain, hook_calls;
static uint8_t hook_out[256];

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in,
		       uint32_t len, const uint8_t **out, uint32_t *out_len)
{
	uint32_t i;

	(void)user;
	hook_calls++;
	memcpy(last_chain, chain, n_chain);
	last_n_chain = n_chain;
	if (!len || in[0] == '!' || len + 2u > sizeof hook_out)
		return 0;
	if (in[0] == '#') {                     /* a value that grows: 200 bytes whatever it was */
		memset(hook_out, 'Z', 200u);
		*out = hook_out;
		*out_len = 200u;
		return 1;
	}
	if (in[0] == '@') {                     /* text with what a display has to spell out: "$", quotes, a break, a control byte, UTF-8 */
		static const char shown[] = "a\nb \"q\" 'r' $x \\ \t\001 \303\251";

		memcpy(hook_out, shown, sizeof shown - 1u);
		*out = hook_out;
		*out_len = (uint32_t)sizeof shown - 1u;
		return 1;
	}
	hook_out[0] = '<';
	for (i = 0; i < len; i++)
		hook_out[1u + i] = (uint8_t)((in[i] >= 'a' && in[i] <= 'z') ? in[i] - 32 : in[i]);
	hook_out[len + 1u] = '>';
	*out = hook_out;
	*out_len = len + 2u;
	return 1;
}

static struct kgenome_textual_form_res dform(const char *src, const char *want, uint32_t flags,
					     uint64_t extra)
{
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src),
					       .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = flags,
					       .out = fbuf, .decode = fake_decode };
	struct kgenome_textual_form_res rs;

	rq.cap = KGENOME_TEXTUAL_FORM_CAP(rq.n) + extra;
	hook_calls = 0;
	last_n_chain = 0;
	kgenome_textual_form(&rq, &rs);
	if (rs.n_out != strlen(want) || memcmp(fbuf, want, rs.n_out)) {
		fbuf[rs.n_out < sizeof fbuf ? rs.n_out : sizeof fbuf - 1u] = 0;
		printf("  FAIL decode of  %s\n       got    %s\n       wanted %s\n", src, fbuf, want);
		fails++;
	}
	return rs;
}

static void decode_hook(void)
{
	struct kgenome_textual_form_res rs;

	rs = dform("<?php f(base64_decode(\"abc\"));", "<?php f(decoded_base64_decode(\"<ABC>\"));", 0, 64);
	CK(rs.n_decoded == 1 && rs.n_refused == 0 && hook_calls == 1);
	CK(last_n_chain == 1 && last_chain[0] == KGENOME_TEXTUAL_DEC_B64);
	/* a chain is given innermost first, whatever order the calls are written in */
	rs = dform("<?php eval(gzinflate(str_rot13(base64_decode('abc'))));",
		   "<?php eval(decoded_gzinflate(decoded_str_rot13(decoded_base64_decode('<ABC>'))));", 0, 64);
	CK(rs.n_decoded == 1 && last_n_chain == 3 && last_chain[0] == KGENOME_TEXTUAL_DEC_B64 &&
	   last_chain[1] == KGENOME_TEXTUAL_DEC_ROT13 && last_chain[2] == KGENOME_TEXTUAL_DEC_INFLATE);
	/* the silence operator, a leading backslash, case and space do not matter; "(" before the name does */
	dform("<?php @\\Strrev( @hex2bin ( \"ab\" ) );", "<?php @\\decoded_Strrev(@decoded_hex2bin(\"<AB>\"));", 0, 64);
	/* php's hex2bin reads digits and nothing between them: its own decoder, where the others' skip separators */
	CK(last_n_chain == 2 && last_chain[0] == KGENOME_TEXTUAL_DEC_HEXSTRICT && last_chain[1] == KGENOME_TEXTUAL_DEC_REVERSE);
	/* the chain stops at the first name that is not a decoder, and a call with another first argument is not read */
	dform("<?php eval(md5(base64_decode(\"ab\")));", "<?php eval(md5(decoded_base64_decode(\"<AB>\")));", 0, 64);
	CK(last_n_chain == 1);
	dform("<?php base64_decode($k, \"ab\");", "<?php base64_decode($k,'ab');", 0, 64);
	CK(hook_calls == 0);
	/* the literals have to be the whole of the argument: a join of literals is the payload (the pieces are valued and
	 * joined), an expression is not, a second argument is kept */
	dform("<?php base64_decode(\"a\" . \"b\");", "<?php decoded_base64_decode(\"<AB>\");", 0, 64);
	CK(hook_calls == 1);
	dform("<?php base64_decode(\"a\" + 1);", "<?php base64_decode('a'+1);", 0, 64);
	CK(hook_calls == 0);
	dform("<?php base64_decode(\"ab\", true);", "<?php decoded_base64_decode(\"<AB>\",true);", 0, 64);
	CK(hook_calls == 1);
	/* a comment or white space between the literal and the bracket is a gap */
	dform("<?php base64_decode( \"ab\" /* c */ );", "<?php decoded_base64_decode(\"<AB>\");", 0, 64);
	CK(hook_calls == 1);
	/* not a decoder, or no call at all, or the literal after a comma */
	dform("<?php md5(\"ab\"); \"cd\"; x(\"ef\");", "<?php md5('ab');'cd';x('ef');", 0, 64);
	CK(hook_calls == 0);
	dform("<?php a(base64_decode(\"x\"), \"y\");", "<?php a(decoded_base64_decode(\"<X>\"),'y');", 0, 64);
	CK(hook_calls == 1);
	/* refused: the literal stays as typed and the refusal is counted */
	rs = dform("<?php base64_decode(\"!ab\");", "<?php base64_decode('!ab');", 0, 64);
	CK(rs.n_decoded == 0 && rs.n_refused == 1 && hook_calls == 1);
	/* a literal that does not close its argument is not offered at all */
	rs = dform("<?php base64_decode(\"ab\" . $x);", "<?php base64_decode('ab'.$x);", 0, 64);
	CK(rs.n_decoded == 0 && rs.n_refused == 0);
	/* a single quoted string and a heredoc are literals too; a heredoc's value ends before its closer's line */
	dform("<?php strrev('ab');", "<?php decoded_strrev('<AB>');", 0, 64);
	/* the hook is given the VALUE: a heredoc's ends before the line break in front of its closer */
	dform("<?php base64_decode(<<<E\nab\nE\n);", "<?php decoded_base64_decode(<<<E\n<AB>E\n);", 0, 64);
	/* a literal still open at the end is not one */
	rs = dform("<?php base64_decode(\"ab", "<?php base64_decode(\"ab", 0, 64);
	CK(hook_calls == 0);
	/* NOT ROOM FOR IT: a value that grows past what the caller left is not decoded, and is counted */
	rs = dform("<?php base64_decode(\"#a\");", "<?php base64_decode('#a');", 0, 0);
	CK(rs.n_decoded == 0 && rs.n_refused == 1);
	/* ...and with the room it needs it is */
	{
		char want[400];
		size_t w = (size_t)snprintf(want, sizeof want, "<?php decoded_base64_decode(\"");

		memset(want + w, 'Z', 200u);
		strcpy(want + w + 200u, "\");");
		rs = dform("<?php base64_decode(\"#a\");", want, 0, 256);
		CK(rs.n_decoded == 1 && rs.n_refused == 0);
	}
	/* no hook, no decoding */
	{
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)"<?php base64_decode(\"ab\");",
						       .n = 26, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = fbuf,
						       .cap = 1024 };
		struct kgenome_textual_form_res r2;

		kgenome_textual_form(&rq, &r2);
		CK(r2.n_decoded == 0 && r2.n_refused == 0 && r2.n_out == 26);
	}
	/* a fragment is code with no tag: lexed from inside, formed, decoded the same way */
	rs = dform("eval( $a ); // c\nbase64_decode( \"ab\" );", "eval($a);\ndecoded_base64_decode(\"<AB>\");",
		   KGENOME_TEXTUAL_FRAGMENT, 64);
	CK(rs.n_decoded == 1);
	dform("a ( ) ; ?> x <?php b ( )", "a();\n?> x <?php b()", KGENOME_TEXTUAL_FRAGMENT, 0);
	dform("", "", KGENOME_TEXTUAL_FRAGMENT, 0);
	dform("// only a comment", "", KGENOME_TEXTUAL_FRAGMENT, 0);
}

/*
 * HOW A DECODED TEXT SHOWS. One double-quoted literal whatever the call was quoted with, inside the calls that were typed,
 * each renamed "decoded_<name>"; a line break is "\n"; the quote, the backslash, "$" (php) and control bytes are escaped,
 * UTF-8 is left; and a join of literals that ends its expression is one literal even where no decoder reads it.
 */
static void display_forms(void)
{
	/* the calls stay - they are how the text came to be - and are named for what the text now is... */
	dform("<?php eval(base64_decode('@'));", "<?php eval(decoded_base64_decode('a\nb \"q\" 'r' $x \\ \t\001 \303\251'));", 0, 64);
	/* ...whatever follows the literal: a second argument or an operator is kept, and the literal is the one form */
	dform("<?php base64_decode('@', true);", "<?php decoded_base64_decode('a\nb \"q\" 'r' $x \\ \t\001 \303\251',true);", 0, 64);
	dform("<?php x(base64_decode('@') . $y);", "<?php x(decoded_base64_decode('a\nb \"q\" 'r' $x \\ \t\001 \303\251').$y);", 0, 64);
	/* a call that is not closed is renamed all the same */
	dform("<?php urldecode(base64_decode('ab');", "<?php decoded_urldecode(decoded_base64_decode('<AB>');", 0, 64);
	/* "return" and the name are two words: only the name is renamed */
	dform("<?php return base64_decode('ab');", "<?php return decoded_base64_decode('<AB>');", 0, 64);
	/* a join no decoder reads */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $f = 'ev' . 'al'; g('a' . \"b\" . 'c');", "<?php $f='eval';g('abc');");
	{
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)"<?php $f = 'ev' . 'al'; g('a' . 'b' . 'c');", .n = 43,
						       .lang = KGENOME_TEXTUAL_LANG_PHP, .out = fbuf, .cap = 256 };
		struct kgenome_textual_form_res rs;

		kgenome_textual_form(&rq, &rs);
		CK(rs.n_folded == 2 && rs.n_decoded == 0);
	}
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $f = 'a' . /* c */ 'b';", "<?php $f='ab';");
	/* ...but not one that goes on in an expression (the next operand binds as it likes), not one that interpolates */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php $f = 'a' . 'b' . $x; $g = 'a' . \"b$x\";", "<?php $f='a'.'b'.$x;$g='a'.\"b$x\";");
	/* echo and print are written as calls, with the bracket round the whole argument; and quotes: single where nothing needs
	 * double (a "$", a backslash or a "'" does), and the same after a second pass */
	form("<?php echo \"x\"; echo(\"x\"); echo ( 'x' ) ; print \"y\" . $z; echo $a ?>t", "<?php echo('x');echo('x');echo('x');print('y'.$z);echo($a)\n?>t");
	form("<?php echo \"a $b\", \"c\\n\"; $echo = 1; $o->echo; echoes(1); echo f(1) . g(2);", "<?php echo(\"a $b\",\"c\\n\");$echo=1;$o->echo;echoes(1);echo(f(1).g(2));");
	form("<?php $a = \"it's\"; $b = \"x\\41\"; $c = \"y\" . 'z' . \"w\";", "<?php $a=\"it's\";$b='x!';$c='yzw';");
	/* a variable at the end of the first text takes what the second begins with, so those two are not one literal */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php f(\"$a\" . \"b$c\"); g(\"$a\" . \"[0]$c\"); h(\"x$\" . \"y$c\"); k(\"$a\" . \"$c\");",
		  "<?php f(\"$a\".\"b$c\");g(\"$a\".\"[0]$c\");h(\"x$\".\"y$c\");k(\"$a$c\");");
	/* only a literal a quote opens is a string being joined */
	form_lang(KGENOME_TEXTUAL_LANG_PHP, "<?php f(<<<E\nx\nE\n . 'a');", "<?php f(<<<E\nx\nE\n.'a');");
	/* KEEP_JOINS: as typed */
	{
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)"<?php $f = 'ev' . 'al';", .n = 23,
						       .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = KGENOME_TEXTUAL_KEEP_JOINS,
						       .out = fbuf, .cap = 256 };
		struct kgenome_textual_form_res rs;

		kgenome_textual_form(&rq, &rs);
		CK(rs.n_out == 19 && memcmp(fbuf, "<?php $f='ev'.'al';", 19) == 0);
	}
}

static void form_status(void)
{
	uint32_t n;
	const char src[] = "<?php a();";

	CK(form_of(src, 10, fbuf, KGENOME_TEXTUAL_FORM_CAP(10) - 1u, &n) == KGENOME_TEXTUAL_SMALL && n == 0);
	CK(form_of(src, 10, fbuf, KGENOME_TEXTUAL_FORM_CAP(10), &n) == KGENOME_TEXTUAL_OK);
	CK(form_of("<?php 'a", 8, fbuf, KGENOME_TEXTUAL_FORM_CAP(8), &n) == KGENOME_TEXTUAL_OPEN);
	{
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = 10, .lang = KGENOME_TEXTUAL_LANG_NONE, .out = fbuf, .cap = sizeof fbuf };
		struct kgenome_textual_form_res rs;

		CK(kgenome_textual_form(&rq, &rs) == KGENOME_TEXTUAL_NO_LANG && rs.n_out == 0);
	}
	CK(KGENOME_TEXTUAL_FORM_CAP(0) == 2u && KGENOME_TEXTUAL_FORM_CAP(100) == 152u);
}

static void form_property(void)
{
	form_property_for(KGENOME_TEXTUAL_LANG_PHP, "<?php=>'\"`/*#[]{}$\\\n\r\t ()<<<EOT;_-a1b+.x4F70", 777u);
	form_property_for(KGENOME_TEXTUAL_LANG_SH, "#!'\"`$(){}\\\n\r\t <<-EOF;|&a1b x", 99u);
}

static void names(void)
{
	CK(!strcmp(kgenome_textual_kind_name(KGENOME_TEXTUAL_MARKUP), "markup"));
	CK(!strcmp(kgenome_textual_kind_name(KGENOME_TEXTUAL_TAG), "tag"));
	CK(!strcmp(kgenome_textual_kind_name(KGENOME_TEXTUAL_CODE), "code"));
	CK(!strcmp(kgenome_textual_kind_name(KGENOME_TEXTUAL_STRING), "string"));
	CK(!strcmp(kgenome_textual_kind_name(KGENOME_TEXTUAL_COMMENT), "comment"));
	CK(!strcmp(kgenome_textual_kind_name(KGENOME_TEXTUAL_KIND_COUNT), "?"));
	CK(!strcmp(kgenome_textual_kind_name(0xffffffffu), "?"));
}

/*
 * THE PARTITION, on input nobody wrote. Bytes drawn from what changes the lexer's mind - quotes,
 * slashes, the tag characters, the heredoc opener, a brace, a dollar, a backslash, line breaks -
 * so a run of them reaches every state and every end-of-input inside every state.
 */
/*
 * THE PARTITION, on input nobody wrote. Bytes drawn from what changes a lexer's mind - quotes, slashes,
 * the characters of its tags and its heredoc openers, braces, a dollar, a backslash, line breaks - so a
 * run of them reaches every state and every end-of-input inside every state.
 */
static void partition(void)
{
	partition_for(KGENOME_TEXTUAL_LANG_PHP, "<?php=>'\"`/*#[]{}$\\\n\r <<<EOT;_-a1", 12345u);
	partition_for(KGENOME_TEXTUAL_LANG_SH, "#!'\"`$(){}\\\n\r\t <<-EOF;|&a1x", 4321u);
}

static void truncation(void)
{
	static const char sample[] =
		"<html><?php /* c */ $a = \"x{$b['}']}y\"; $c = <<<EOT\nbody\n EOT;\n// d ?>t<?= `ls` ?>\n"
		"<?php __halt_compiler(); data";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, KGENOME_TEXTUAL_LANG_PHP);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* and the whole of it reads as written */
	expect(sample,
	       "M{<html>}T{<?php }K{/* c */}C{ $a = }S*{\"x{$b['}']}y\"}C{; $c = }S*#{<<<EOT\nbody\n EOT}C{;\n}K{// d }"
	       "T{?>}M{t}T{<?=}C{ }S*{`ls`}C{ }T{?>\n}T{<?php }C{__halt_compiler();}M{ data}");
}

int main(void)
{
	tags();
	comments();
	strings();
	heredocs();
	halt();
	sh_lexer();
	status();
	forms();
	sh_forms();
	decode_hook();
	display_forms();
	form_status();
	names();
	partition();
	form_property();
	truncation();
	printf("textual api: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
