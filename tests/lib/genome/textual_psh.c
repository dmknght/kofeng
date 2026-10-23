/*
 * genome / textual_psh - the PowerShell lexer, form and value of the textual part, through <kgenome.h> alone.
 *
 * NO PowerShell IS ON THE MACHINE THIS WAS WRITTEN ON, so nothing here is "an interpreter agrees". What is asserted,
 * and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS, one per rule of psh_lex.c with the neighbour it could be confused for: a case is the text and
 *       the one line it must come out as (kind letter, bytes in braces; S* = it interpolates and escapes, S! = not
 *       closed, S# = here-string - see textual_check.h). A case whose rule rests on memory of the language and not on
 *       a source read here says [Unverified] where it stands: the case pins what the lexer does, not what the
 *       language does.
 *   (b) A GENERATOR of programs (textual_psh_gen.h): every literal, comment and run of code is laid out with its
 *       kind, offset, delimiters and flags known, in one of three line-ending styles, and the lexer's spans must
 *       equal them byte for byte; the VALUE of every literal the generator can know is compared with the value hook;
 *       the form must keep every string as typed and no comment, and be its own form. (The programs are valid by
 *       the rules of the lexer, not by an interpreter's word.)
 *   (c) THE PARTITION and the idempotence of the form on random bytes, on random text from the language's own
 *       alphabet and on text assembled from its delimiters, a text cut at every length, nesting past the bound,
 *       NUL bytes and the three line endings, and hostile texts read in time linear in them.
 *   (d) FORM, VALUE and DECODER known answers; the decode hook is a fake one (the contract is what is asserted).
 *
 * Everything goes through <kgenome.h> and nothing else: a test of a language is a test of the API.
 */

#include "textual_psh_gen.h"

#include <time.h>

#define PSH KGENOME_TEXTUAL_LANG_PSH

static void ps(const char *src, const char *want)
{
	expect_lang(PSH, src, want);
}

static void comments(void)
{
	ps("a # b\nc", "C{a }K{# b}C{\nc}");
	ps("# only", "K{# only}");
	ps("#a\r\nb", "K{#a}C{\r\nb}");
	ps("#a\rb", "K{#a}C{\rb}");
	/* a "#" inside a word is the word's [Unverified: the tokenizer as remembered; VS Code's grammar makes it a comment] */
	ps("echo a#b", "C{echo a#b}");
	ps("cd C:\\C#\\x", "C{cd C:\\C#\\x}");
	/* where a token begins it is a comment: after a blank, ";", "|", "&", "(", "{", "}", ")", ",", "]", at the start */
	ps("a;#b", "C{a;}K{#b}");
	ps("a|#b", "C{a|}K{#b}");
	ps("(#b\n)", "C{(}K{#b}C{\n)}");
	ps("a,#b", "C{a,}K{#b}");
	ps("$a[0]#b", "C{$a[0]}K{#b}");
	ps("{#b\n}", "C{{}K{#b}C{\n}}");
	/* a name ends at "#": "$x#c" is a variable and a comment [Unverified]; "$env:x#c" too; "$x.y#c" is not a variable name */
	ps("$x#c", "C{$x}K{#c}");
	ps("$env:x#c", "C{$env:x}K{#c}");
	ps("$x.y#c", "C{$x.y#c}");
	/* right after a string or a comment a token has ended */
	ps("'a'#c", "S{'a'}K{#c}");
	ps("\"a\"#c", "S*{\"a\"}K{#c}");
	ps("<#a#>#c", "K{<#a#>}K{#c}");
	/* a backtick before it escapes it */
	ps("a `#b", "C{a `#b}");
	/* a byte order mark is not a word */
	ps("\xef\xbb\xbf" "# c\nx", "C{\xef\xbb\xbf}K{# c}C{\nx}");
	ps("#!/usr/bin/env pwsh\nx", "K{#!/usr/bin/env pwsh}C{\nx}");
	/* block comments hold line breaks, quotes and "#"; they do not nest; "<#>" does not close itself */
	ps("a <# b\n c #> d", "C{a }K{<# b\n c #>}C{ d}");
	ps("<# ' \" @' $( # #>x", "K{<# ' \" @' $( # #>}C{x}");
	ps("<# a <# b #> c #>", "K{<# a <# b #>}C{ c }K{#>}");
	ps("<##>x", "K{<##>}C{x}");
	ps("<###>x", "K{<###>}C{x}");
	ps("<#>", "K!{<#>}");
	ps("<#>#>x", "K{<#>#>}C{x}");
	ps("<# x", "K!{<# x}");
	ps("<#", "K!{<#}");
	ps("<# x #", "K!{<# x #}");
	/* "<#" is a comment only where a token begins, as "#" is */
	ps("a<#b#>", "C{a<#b#>}");
	ps("a <#b#>c", "C{a }K{<#b#>}C{c}");
	/* a "#" in a line comment, and the comment's end at the break of any of the three kinds */
	ps("#a#b\n#c", "K{#a#b}C{\n}K{#c}");
	ps("x #\r\ny", "C{x }K{#}C{\r\ny}");
}

static void singles(void)
{
	ps("'a' 'b'", "S{'a'}C{ }S{'b'}");
	ps("'it''s'", "S{'it''s'}");
	ps("'a''' x", "S{'a'''}C{ x}");
	ps("''", "S{''}");
	ps("'''", "S!{'''}");
	ps("''''", "S{''''}");
	ps("'a\nb'", "S{'a\nb'}");
	/* a backslash and a backtick are nothing in a single quoted string; "#" and the other quote are text */
	ps("'a\\' x", "S{'a\\'}C{ x}");
	ps("'a`' x", "S{'a`'}C{ x}");
	ps("'# \" $( <# @'", "S{'# \" $( <# @'}");
	ps("'abc", "S!{'abc}");
	ps("'", "S!{'}");
	/* typographic single quotes are quote characters, in any mix; UTF-8 bytes E2 80 98..9B */
	ps("\xe2\x80\x98" "a\xe2\x80\x99 x", "S{\xe2\x80\x98" "a\xe2\x80\x99}C{ x}");
	ps("\xe2\x80\x9a" "a\xe2\x80\x9b", "S{\xe2\x80\x9a" "a\xe2\x80\x9b}");
	ps("'a\xe2\x80\x99 x", "S{'a\xe2\x80\x99}C{ x}");
	ps("\xe2\x80\x98" "a' x", "S{\xe2\x80\x98" "a'}C{ x}");
	/* a quote character right before the closer makes a pair with it, whichever two they are: the string goes on */
	ps("\xe2\x80\x98" "a'\xe2\x80\x99 x", "S!{\xe2\x80\x98" "a'\xe2\x80\x99 x}");
	ps("\xe2\x80\x98" "a\xe2\x80\x99\xe2\x80\x99" "b\xe2\x80\x99", "S{\xe2\x80\x98" "a\xe2\x80\x99\xe2\x80\x99" "b\xe2\x80\x99}");
	ps("\xe2\x80\x98" "a\"b#\xe2\x80\x99 x", "S{\xe2\x80\x98" "a\"b#\xe2\x80\x99}C{ x}");
	/* the neighbours of the three bytes: U+2017 and U+201C are not single quotes, U+201C is a double one */
	ps("\xe2\x80\x97 'a'", "C{\xe2\x80\x97 }S{'a'}");
	ps("\xe2\x80\x9c" "a\xe2\x80\x9d", "S*{\xe2\x80\x9c" "a\xe2\x80\x9d}");
	/* a truncated sequence is no quote */
	ps("\xe2\x80", "C{\xe2\x80}");
	ps("\xe2", "C{\xe2}");
}

static void doubles(void)
{
	ps("\"a\" \"b\"", "S*{\"a\"}C{ }S*{\"b\"}");
	/* the backtick escapes the byte after it, a quote included; the doubled quote is the second escape */
	ps("\"a`\"b\" x", "S*{\"a`\"b\"}C{ x}");
	ps("\"a\"\"b\" x", "S*{\"a\"\"b\"}C{ x}");
	ps("\"a``\" x", "S*{\"a``\"}C{ x}");
	ps("\"\"", "S*{\"\"}");
	ps("\"\"\"", "S*!{\"\"\"}");
	ps("\"\"\"\"", "S*{\"\"\"\"}");
	ps("\"a`", "S*!{\"a`}");
	ps("\"a\nb\" x", "S*{\"a\nb\"}C{ x}");
	ps("\"a'b # c\" x", "S*{\"a'b # c\"}C{ x}");
	ps("\"a", "S*!{\"a}");
	/* interpolation: names, braces, sub-expressions */
	ps("\"$x $env:Path $_ $?\" y", "S*{\"$x $env:Path $_ $?\"}C{ y}");
	ps("\"${a b} c\" y", "S*{\"${a b} c\"}C{ y}");
	ps("\"${a\"b} c\" y", "S*{\"${a\"b} c\"}C{ y}");
	ps("\"${a`}b} c\" y", "S*{\"${a`}b} c\"}C{ y}");
	ps("\"${a", "S*!{\"${a}");
	ps("\"$(1+1)\" y", "S*{\"$(1+1)\"}C{ y}");
	ps("\"a $(\"b\") c\" y", "S*{\"a $(\"b\") c\"}C{ y}");
	ps("\"$(')')\" y", "S*{\"$(')')\"}C{ y}");
	ps("\"$(# c )\n1)\" y", "S*{\"$(# c )\n1)\"}C{ y}");
	ps("\"$(<# ) #> 1)\" y", "S*{\"$(<# ) #> 1)\"}C{ y}");
	ps("\"$(${a)}b)\" y", "S*{\"$(${a)}b)\"}C{ y}");
	ps("\"$((1+2)*3)\" y", "S*{\"$((1+2)*3)\"}C{ y}");
	ps("\"$(\"$(\"x\")\")\" y", "S*{\"$(\"$(\"x\")\")\"}C{ y}");
	ps("\"$(@'\nh)\n'@)\" y", "S*{\"$(@'\nh)\n'@)\"}C{ y}");
	ps("\"$(`)`\")\" y", "S*{\"$(`)`\")\"}C{ y}");
	/* a sub-expression that does not close opens the string to the end, whatever follows */
	ps("\"a $(1 \" x", "S*!{\"a $(1 \" x}");
	ps("\"a $(", "S*!{\"a $(}");
	/* "$$", "$?", "$^" are variables, so what follows is text; a backtick, "@(" and a lone "$" are text */
	ps("\"$$(\" x", "S*{\"$$(\"}C{ x}");
	ps("\"$?(\" x", "S*{\"$?(\"}C{ x}");
	ps("\"`$(\" x", "S*{\"`$(\"}C{ x}");
	ps("\"@(\" x", "S*{\"@(\"}C{ x}");
	ps("\"$\" x", "S*{\"$\"}C{ x}");
	ps("\"$ (\" x", "S*{\"$ (\"}C{ x}");
	/* typographic double quotes are quote characters too (E2 80 9C..9E), and escape pairs of their own */
	ps("\xe2\x80\x9c" "a\xe2\x80\x9d x", "S*{\xe2\x80\x9c" "a\xe2\x80\x9d}C{ x}");
	ps("\xe2\x80\x9e" "a\" x", "S*{\xe2\x80\x9e" "a\"}C{ x}");
	ps("\xe2\x80\x9e" "a\"\" x", "S*!{\xe2\x80\x9e" "a\"\" x}");
	ps("\xe2\x80\x9c" "a\xe2\x80\x9d\xe2\x80\x9d" "b\xe2\x80\x9d x", "S*{\xe2\x80\x9c" "a\xe2\x80\x9d\xe2\x80\x9d" "b\xe2\x80\x9d}C{ x}");
	ps("\"a`\xe2\x80\x9d" "b\" x", "S*{\"a`\xe2\x80\x9d" "b\"}C{ x}");
	ps("\"a\xe2\x80\x9c x", "S*{\"a\xe2\x80\x9c}C{ x}");
}

static void heres(void)
{
	ps("@'\nabc\n'@", "S#{@'\nabc\n'@}");
	ps("@\"\n$x\n\"@ | iex", "S*#{@\"\n$x\n\"@}C{ | iex}");
	ps("x = @'\r\nabc\r\n'@\r\ny", "C{x = }S#{@'\r\nabc\r\n'@}C{\r\ny}");
	ps("@'  \nabc\n'@", "S#{@'  \nabc\n'@}");
	ps("@'\t\nabc\n'@", "S#{@'\t\nabc\n'@}");
	ps("@'\n'@", "S#{@'\n'@}");
	ps("@'\n\n'@", "S#{@'\n\n'@}");
	/* the closer begins a line: indented, mid-line and of the other kind it is body */
	ps("@'\nx\n  '@\n'@", "S#{@'\nx\n  '@\n'@}");
	ps("@'\nx'@\n'@", "S#{@'\nx'@\n'@}");
	ps("@'\nx\n\"@\n'@", "S#{@'\nx\n\"@\n'@}");
	ps("@\"\nx\n'@\n\"@", "S*#{@\"\nx\n'@\n\"@}");
	/* what follows the closer on its line is code */
	ps("@'\nx\n'@.Length", "S#{@'\nx\n'@}C{.Length}");
	/* "@'" must be the last thing on its line; otherwise "@" is code and the quote opens a string */
	ps("@'x'", "C{@}S{'x'}");
	ps("@' x\n'@", "C{@}S{' x\n'}C{@}");
	ps("@'", "C{@}S!{'}");
	ps("@\"", "C{@}S*!{\"}");
	ps("@'\r", "S!#{@'\r}");
	/* a here-string that never closes runs to the end */
	ps("@'\nabc", "S!#{@'\nabc}");
	ps("@'\nabc\n'", "S!#{@'\nabc\n'}");
	/* a double quoted one skips what interpolates: a closer line inside a sub-expression's string is not a closer */
	ps("@\"\n$(1 +\n2)\n\"@", "S*#{@\"\n$(1 +\n2)\n\"@}");
	ps("@\"\n$(\"a\n\"@\n\"b\")\n\"@", "S*#{@\"\n$(\"a\n\"@\n\"b\")\n\"@}");
	ps("@\"\n$(1\n\"@", "S*!#{@\"\n$(1\n\"@}");
	ps("@\"\n`\"@\n\"@", "S*#{@\"\n`\"@\n\"@}");
	ps("@\"\n$$(\n\"@", "S*#{@\"\n$$(\n\"@}");
	/* typographic quotes of the class, as opener and as closer */
	ps("@\xe2\x80\x98\nx\n\xe2\x80\x99@", "S#{@\xe2\x80\x98\nx\n\xe2\x80\x99@}");
	ps("@\xe2\x80\x9c\nx\n\xe2\x80\x9d@", "S*#{@\xe2\x80\x9c\nx\n\xe2\x80\x9d@}");
	/* splatting and arrays are not here-strings */
	ps("f @args @(1) @{a=1}", "C{f @args @(1) @{a=1}}");
	ps("f @'a' @\"b\"", "C{f @}S{'a'}C{ @}S*{\"b\"}");
}

static void code(void)
{
	/* the backtick escapes the byte after it; a line continuation is a backtick and a break */
	ps("a `'b c", "C{a `'b c}");
	ps("a `\"b c", "C{a `\"b c}");
	ps("a `'b' c", "C{a `'b}S!{' c}");
	ps("a `\nb 'x'", "C{a `\nb }S{'x'}");
	ps("a `\r\nb 'x'", "C{a `\r\nb }S{'x'}");
	ps("a`", "C{a`}");
	ps("``'x'", "C{``}S{'x'}");
	ps("i`ex 'x'", "C{i`ex }S{'x'}");
	/* "${...}" in code is a name that may hold quotes and "#"; unclosed it is two bytes of code */
	ps("${a'b} 'c'", "C{${a'b} }S{'c'}");
	ps("${a#b} 'c'", "C{${a#b} }S{'c'}");
	ps("${a`}'b} 'c'", "C{${a`}'b} }S{'c'}");
	ps("${a", "C{${a}");
	ps("${a\n'b'", "C{${a\n}S{'b'}");
	ps("${ ${ '", "C{${ ${ }S!{'}");
	ps("$'x'", "C{$}S{'x'}");
	/* numbers with suffixes, type literals and calls are code */
	ps("1KB 0x1F 2.5e3 1MB", "C{1KB 0x1F 2.5e3 1MB}");
	ps("[Convert]::FromBase64String('YQ==')", "C{[Convert]::FromBase64String(}S{'YQ=='}C{)}");
	ps("& $x; . $y", "C{& $x; . $y}");
	ps("[System.Convert]::FromBase64String(\"YQ==\")", "C{[System.Convert]::FromBase64String(}S*{\"YQ==\"}C{)}");
	ps("", "");
	/* the real stager's shape: a format operator and call operator are code */
	ps("&('{1}{0}' -f 'R','IW') x", "C{&(}S{'{1}{0}'}C{ -f }S{'R'}C{,}S{'IW'}C{) x}");
}

static void forms(void)
{
	/* white space is syntax: one space where there was any; a line break is kept, once; comments go */
	form_lang(PSH, "Get-Item   -Path  'x'  <# c #>  | out", "Get-Item -Path 'x' | out");
	form_lang(PSH, "a # c\nb", "a\nb");
	form_lang(PSH, "a\n\n\n   b  # c", "a\nb");
	form_lang(PSH, "a\r\nb", "a\nb");
	form_lang(PSH, "'a  #  b' \"c  d\"", "'a  #  b' \"c  d\"");
	form_lang(PSH, "x = @'\n  a  \n'@", "x = @'\n  a  \n'@");
	form_lang(PSH, "\"a\"<#c#>\"b\"", "\"a\" \"b\"");
	form_lang(PSH, "'a'<#c#>'b'", "'a' 'b'");
	/* kept: a comment that is not closed, the first line that names the interpreter */
	form_lang(PSH, "x <# y", "x <# y");
	form_lang(PSH, "#!/usr/bin/env pwsh\n# c\nx", "#!/usr/bin/env pwsh\nx");
	/* a join of literals with the same quotes, where it ends its expression, is one literal */
	/* the join is read for a decoder, and never written as one literal (nofold) */
	form_lang(PSH, "iex ('Inv'+'oke')", "iex ('Inv'+'oke')");
	form_lang(PSH, "f('a' + 'b', 'c'+'d')", "f('a' + 'b', 'c'+'d')");
	form_lang(PSH, "f('a' + \"b\")", "f('a' + \"b\")");
	/* the continuation as it is written: the backtick and its break stay, the indentation after them goes (psh_lang.c) */
	form_lang(PSH, "a `\n    b", "a `\n b");     /* after a continuation the next line is the same line: its indentation is a separator */
	form_lang(PSH, "x #c\ry", "x y");
}

/* ---- the value of a literal ---- */

static void val(const char *lit, uint32_t open, uint32_t close, uint8_t flags, const char *want)
{
	uint8_t out[256];
	struct kgenome_textual_value_req rq = { .lang = PSH, .lit = (const uint8_t *)lit, .len = (uint32_t)strlen(lit),
						.open_len = open, .close_len = close, .flags = flags, .out = out, .cap = sizeof out };
	struct kgenome_textual_value_res rs;
	enum kgenome_textual_status st = kgenome_textual_value(&rq, &rs);

	if (!want) {
		if (st != KGENOME_TEXTUAL_NO_VALUE) {
			printf("  FAIL value of  %s  was given (status %d), wanted none\n", lit, (int)st);
			fails++;
		}
		return;
	}
	if (st != KGENOME_TEXTUAL_OK || rs.n_out != strlen(want) || memcmp(out, want, rs.n_out)) {
		printf("  FAIL value of  %s  (status %d, %u bytes), wanted %s\n", lit, (int)st, rs.n_out, want);
		fails++;
	}
}

static void values(void)
{
	const uint8_t I = KGENOME_TEXTUAL_F_INTERP, H = KGENOME_TEXTUAL_F_HERE;

	/* single quotes: the text, and the doubled quote */
	val("'a\\n`n'", 1, 1, 0, "a\\n`n");
	val("'it''s'", 1, 1, 0, "it's");
	val("''''", 1, 1, 0, "'");
	val("'a\xe2\x80\x99\xe2\x80\x99" "b'", 1, 1, 0, NULL);          /* a pair that is typographic: which one stays is not known */
	val("\xe2\x80\x98" "ab\xe2\x80\x99", 3, 3, 0, "ab");
	/* double quotes: the backtick escapes, the doubled quote, a dollar that is not a variable */
	val("\"a`nb`tc\"", 1, 1, I, "a\nb\tc");
	val("\"a`\"b\"\"c``d`$e`'f`xg\"", 1, 1, I, "a\"b\"c`d$e'fxg");
	val("\"a`ab`bc`fd`re`vf\"", 1, 1, I, "a\ab\bc\fd\re\vf");
	val("\"$ a $\"", 1, 1, I, "$ a $");
	val("\"@(1) {x} (y)\"", 1, 1, I, "@(1) {x} (y)");
	val("\"a`$b\"", 1, 1, I, "a$b");
	val("\xe2\x80\x9c" "a`\xe2\x80\x9d" "b\xe2\x80\x9d", 3, 3, I, "a\xe2\x80\x9d" "b");
	val("\"a\xe2\x80\x9d\xe2\x80\x9d" "b\"", 1, 1, I, NULL);
	/* no value where the program computes it, or where the language's version decides */
	val("\"$x\"", 1, 1, I, NULL);
	val("\"a ${b} c\"", 1, 1, I, NULL);
	val("\"$(1)\"", 1, 1, I, NULL);
	val("\"$$\"", 1, 1, I, NULL);
	val("\"$?\"", 1, 1, I, NULL);
	val("\"$_ $1 $env:x\"", 1, 1, I, NULL);
	val("\"a`eb\"", 1, 1, I, NULL);
	val("\"a`u{41}b\"", 1, 1, I, NULL);
	val("\"a`\nb\"", 1, 1, I, NULL);
	val("\"abc", 1, 0, (uint8_t)(I | KGENOME_TEXTUAL_F_OPEN), NULL);
	/* here-strings: the body, verbatim for @' and read as "..." for @" (except that a quote is a quote) */
	val("@'\nab\\n`n\n'@", 3, 3, H, "ab\\n`n");
	val("@'\r\nab\r\n'@", 4, 4, H, "ab");
	val("@'\n'@", 3, 2, H, "");
	val("@'\n\n'@", 3, 3, H, "");
	val("@'\n''\n'@", 3, 3, H, "''");
	val("@\"\na`nb\"\"\n\"@", 3, 3, (uint8_t)(H | I), "a\nb\"\"");
	val("@\"\n$x\n\"@", 3, 3, (uint8_t)(H | I), NULL);
}

/* ---- the decode hook, with a decoder that is not one ---- */

static uint8_t last_chain[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t last_n_chain, hook_calls;
static uint8_t hook_out[512], hook_in[512];
static uint32_t hook_in_len;

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
		       const uint8_t **out, uint32_t *out_len)
{
	uint32_t i;

	(void)user;
	hook_calls++;
	memcpy(last_chain, chain, n_chain);
	last_n_chain = n_chain;
	if (len < sizeof hook_in) {
		memcpy(hook_in, in, len);
		hook_in_len = len;
	}
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
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = PSH,
					       .out = fbuf, .decode = fake_decode };
	struct kgenome_textual_form_res rs;

	rq.cap = KGENOME_TEXTUAL_FORM_CAP(rq.n) + 64u;
	hook_calls = last_n_chain = hook_in_len = 0;
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

static int hook_got(const char *s)
{
	return hook_in_len == strlen(s) && !memcmp(hook_in, s, hook_in_len);
}

static void decoders(void)
{
	static const uint8_t b64[] = { KGENOME_TEXTUAL_DEC_B64 }, hex[] = { KGENOME_TEXTUAL_DEC_HEX },
		url[] = { KGENOME_TEXTUAL_DEC_URL }, rawurl[] = { KGENOME_TEXTUAL_DEC_RAWURL };
	struct kgenome_textual_form_res rs;

	/* the call, qualified or not, in either case, with single quotes or double, spaced or not */
	rs = dform("[Convert]::FromBase64String('abc')", "[Convert]::decoded_FromBase64String('<ABC>')");
	CK(rs.n_decoded == 1 && rs.n_refused == 0 && hook_calls == 1 && chain_is(1, b64));
	dform("[System.Convert]::frombase64string(\"abc\")", "[System.Convert]::decoded_frombase64string(\"<ABC>\")");
	CK(chain_is(1, b64));
	dform("$b = [CONVERT]::FROMBASE64STRING ( 'abc' ) ;", "$b = [CONVERT]::decoded_FROMBASE64STRING( '<ABC>' ) ;");
	CK(chain_is(1, b64));
	/* what is around it stays: the text decoding is not a decoder this lib has, so the call over it ends the chain */
	dform("[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('abc'))",
	      "[Text.Encoding]::Unicode.GetString([Convert]::decoded_FromBase64String('<ABC>'))");
	CK(chain_is(1, b64) && hook_calls == 1);
	dform("$ser = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('abc')));",
	      "$ser = $([Text.Encoding]::Unicode.GetString([Convert]::decoded_FromBase64String('<ABC>')));");
	/* a second argument is not the payload's end, and the first literal still is the payload */
	dform("[Convert]::FromBase64String('ab', $x)", "[Convert]::decoded_FromBase64String('<AB>', $x)");
	/* hex and the percent codings */
	dform("[Convert]::FromHexString('41')", "[Convert]::decoded_FromHexString('<41>')");
	CK(chain_is(1, hex));
	dform("[Uri]::UnescapeDataString('%41')", "[Uri]::decoded_UnescapeDataString('<%41>')");
	CK(chain_is(1, rawurl));
	dform("[System.Web.HttpUtility]::UrlDecode('%41')", "[System.Web.HttpUtility]::decoded_UrlDecode('<%41>')");
	CK(chain_is(1, url));
	/* a "+" is read two ways by those, and each is its own decoder: UnescapeDataString keeps it (RAW), UrlDecode reads it as a space */
	rs = dform("[Uri]::UnescapeDataString('a+b')", "[Uri]::decoded_UnescapeDataString('<A+B>')");
	CK(hook_calls == 1 && rs.n_refused == 0 && chain_is(1, rawurl));
	rs = dform("[System.Web.HttpUtility]::UrlDecode('a+b')", "[System.Web.HttpUtility]::decoded_UrlDecode('<A+B>')");
	CK(hook_calls == 1 && chain_is(1, url));
	/* the value is what the decoder reads: a doubled quote is one, a backtick escape is applied */
	dform("[Convert]::FromBase64String('a''b')", "[Convert]::decoded_FromBase64String('<A'B>')");
	CK(hook_got("a'b"));
	dform("[Convert]::FromBase64String(\"a`\"b\"\"c`$d\")", "[Convert]::decoded_FromBase64String(\"<A\"B\"C$D>\")");
	CK(hook_got("a\"b\"c$d"));
	dform("[Convert]::FromBase64String(\"a`nb\")", "[Convert]::decoded_FromBase64String(\"<A\nB>\")");
	CK(hook_got("a\nb"));
	/* a join of literals is one payload */
	dform("[Convert]::FromBase64String('ab'+'cd')", "[Convert]::decoded_FromBase64String('<ABCD>')");
	CK(hook_got("abcd"));
	/* a here-string is the payload without its closing line break, and the output keeps the closer on its line */
	dform("[Convert]::FromBase64String(@'\nabc\n'@)", "[Convert]::decoded_FromBase64String(@'\n<ABC>\n'@)");
	CK(hook_got("abc"));
	/* NOT a payload: a variable, an interpolating string, an expression, a call that is not a decoder */
	dform("[Convert]::FromBase64String($x)", "[Convert]::FromBase64String($x)");
	CK(hook_calls == 0);
	rs = dform("[Convert]::FromBase64String(\"a$b\")", "[Convert]::FromBase64String(\"a$b\")");
	CK(hook_calls == 0 && rs.n_refused == 1);
	dform("[Convert]::FromBase64String('ab'.Trim())", "[Convert]::FromBase64String('ab'.Trim())");
	CK(hook_calls == 0);
	dform("[Text.Encoding]::UTF8.GetString('abc'); my_FromBase64String('ab'); [Convert]::ToBase64String('ab')",
	      "[Text.Encoding]::UTF8.GetString('abc'); my_FromBase64String('ab'); [Convert]::ToBase64String('ab')");
	CK(hook_calls == 0);
	/* refused by the hook: as typed, and said; one that is not closed is not offered */
	rs = dform("[Convert]::FromBase64String('!ab')", "[Convert]::FromBase64String('!ab')");
	CK(rs.n_decoded == 0 && rs.n_refused == 1 && hook_calls == 1);
	dform("[Convert]::FromBase64String('ab", "[Convert]::FromBase64String('ab");
	CK(hook_calls == 0);
	/* a comment between the call and the literal is a gap */
	dform("[Convert]::FromBase64String( <# c #> 'ab' # d\n )", "[Convert]::decoded_FromBase64String( '<AB>'\n)");
	CK(hook_calls == 1);
}

/* ---- (b) the generator ---- */

static struct gen gg;
static struct { struct gspan sp[G_SPANS]; uint32_t n; } got;

static int collect(void *u, const struct kgenome_textual_span *s)
{
	(void)u;
	if (got.n < G_SPANS) {
		struct gspan *g = &got.sp[got.n++];

		memset(g, 0, sizeof *g);
		g->off = s->off;
		g->len = s->len;
		g->open = s->open_len;
		g->close = s->close_len;
		g->kind = s->kind;
		g->flags = s->flags;
	}
	return 1;
}

static void show(const char *b, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n && i < 400u; i++)
		printf((uint8_t)b[i] >= 0x20 && (uint8_t)b[i] < 0x7f && b[i] != '\\' ? "%c" : "\\x%02x", (uint8_t)b[i]);
	printf("\n");
}

static uint8_t outa[G_MAX * 2u], outb[G_MAX * 2u];

static int has_bytes(const uint8_t *h, uint32_t hn, const uint8_t *s, uint32_t sn)
{
	uint32_t i;

	for (i = 0; i + sn <= hn; i++)
		if (!memcmp(h + i, s, sn))
			return 1;
	return sn == 0;
}

/* The form of one generated program: every string kept as typed, no comment kept, the form of the form is itself. */
static int check_form(const struct gen *g)
{
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)g->buf, .n = g->n, .lang = PSH, .out = outa,
					       .cap = KGENOME_TEXTUAL_FORM_CAP(g->n) };
	struct kgenome_textual_form_res rs, rs2;
	uint32_t i;
	int open_comment = 0;

	if (kgenome_textual_form(&rq, &rs) == KGENOME_TEXTUAL_SMALL)
		return 0;
	for (i = 0; i < g->ns; i++) {
		const struct gspan *s = &g->sp[i];

		if (s->kind == KGENOME_TEXTUAL_STRING &&
		    !has_bytes(outa, rs.n_out, (const uint8_t *)g->buf + s->off, s->len))
			return 0;
		open_comment |= s->kind == KGENOME_TEXTUAL_COMMENT && (s->flags & KGENOME_TEXTUAL_F_OPEN);
	}
	if (!open_comment && has_bytes(outa, rs.n_out, (const uint8_t *)"zQ9", 3))
		return 0;
	rq = (struct kgenome_textual_form_req){ .in = outa, .n = rs.n_out, .lang = PSH, .out = outb,
						.cap = KGENOME_TEXTUAL_FORM_CAP(rs.n_out) };
	kgenome_textual_form(&rq, &rs2);
	return rs2.n_out == rs.n_out && !memcmp(outa, outb, rs.n_out);
}

static int check_values(const struct gen *g)
{
	uint32_t i;
	static uint8_t v[G_MAX];

	for (i = 0; i < g->ns; i++) {
		const struct gspan *s = &g->sp[i];
		struct kgenome_textual_value_req rq;
		struct kgenome_textual_value_res rs;

		if (!s->has_val)
			continue;
		rq = (struct kgenome_textual_value_req){ .lang = PSH, .lit = (const uint8_t *)g->buf + s->off, .len = s->len,
							 .open_len = s->open, .close_len = s->close, .flags = s->flags, .out = v,
							 .cap = sizeof v };
		if (kgenome_textual_value(&rq, &rs) != KGENOME_TEXTUAL_OK || rs.n_out != s->val_len ||
		    memcmp(v, g->vals + s->val_off, s->val_len))
			return 0;
	}
	return 1;
}

static void generator(void)
{
	uint32_t seed, bad = 0, skipped = 0, made = 0, opened = 0;

	for (seed = 1; seed <= 6000u && bad < 3u; seed++) {
		struct kgenome_textual_lex_req rq;
		struct kgenome_textual_lex_res rs;
		uint32_t i;
		int ok = 1;

		g_program(&gg, seed);
		if (gg.full) {
			skipped++;
			continue;
		}
		made++;
		got.n = 0;
		rq = (struct kgenome_textual_lex_req){ .in = (const uint8_t *)gg.buf, .n = gg.n, .lang = PSH, .sink = collect };
		kgenome_textual_lex(&rq, &rs);
		opened += rs.n_open != 0;
		if (got.n != gg.ns) {
			ok = 0;
		} else {
			for (i = 0; i < gg.ns && ok; i++) {
				const struct gspan *a = &got.sp[i], *b = &gg.sp[i];

				ok = a->off == b->off && a->len == b->len && a->kind == b->kind && a->flags == b->flags &&
				     a->open == b->open && a->close == b->close;
			}
		}
		if (!ok || !check_values(&gg) || !check_form(&gg)) {
			printf("  FAIL generated program %u (%s%s)\n  ", seed, ok ? "" : "spans differ", ok ? "values or form" : "");
			show(gg.buf, gg.n);
			if (!ok) {
				for (i = 0; i < gg.ns || i < got.n; i++)
					printf("    [%u] want off=%u len=%u kind=%u fl=%u o=%u c=%u | got off=%u len=%u kind=%u fl=%u o=%u c=%u\n", i,
					       i < gg.ns ? gg.sp[i].off : 0, i < gg.ns ? gg.sp[i].len : 0, i < gg.ns ? gg.sp[i].kind : 9,
					       i < gg.ns ? gg.sp[i].flags : 0, i < gg.ns ? gg.sp[i].open : 0, i < gg.ns ? gg.sp[i].close : 0,
					       i < got.n ? got.sp[i].off : 0, i < got.n ? got.sp[i].len : 0, i < got.n ? got.sp[i].kind : 9,
					       i < got.n ? got.sp[i].flags : 0, i < got.n ? got.sp[i].open : 0, i < got.n ? got.sp[i].close : 0);
			}
			fails++;
			bad++;
		}
	}
	CK(made > 5000u);
	CK(opened > 300u && opened < made);
	printf("  generator: %u programs checked, %u thrown away for size, %u of them not closed\n", made, skipped, opened);
}

/* ---- (c) any text at all ---- */

/* Text assembled from the language's delimiters, so that here-strings, sub-expressions and comments actually form. */
static void pieces_property(uint32_t seed)
{
	static const char *const piece[] = {
		"@'", "'@", "@\"", "\"@", "$(", ")", "${", "}", "<#", "#>", "#", "`", "\n", "\r\n", "\r", "'", "\"", "''", "\"\"",
		"\xe2\x80\x98", "\xe2\x80\x99", "\xe2\x80\x9c", "\xe2\x80\x9d", " ", "x", "$", "$$", "@", ";", "(", "`\n", "\t"
	};
	static struct rend r;
	static char b[2048];
	uint32_t s = seed, i, k, n, w1, w2;

	for (i = 0; i < 40000u; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		enum kgenome_textual_status st;

		s = s * 1103515245u + 12345u;
		k = 1u + (s >> 16) % 40u;
		for (n = 0; k--;) {
			const char *p;

			s = s * 1103515245u + 12345u;
			p = piece[(s >> 16) % (sizeof piece / sizeof piece[0])];
			memcpy(b + n, p, strlen(p));
			n += (uint32_t)strlen(p);
		}
		lex(&r, b, n, PSH);
		if (r.broken) {
			printf("  FAIL partition on assembled text of %u bytes\n  ", n);
			show(b, n);
			fails++;
			return;
		}
		rq = (struct kgenome_textual_form_req){ .in = (const uint8_t *)b, .n = n, .lang = PSH, .out = fbuf, .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
		st = kgenome_textual_form(&rq, &rs);
		w1 = rs.n_out;
		if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || w1 > KGENOME_TEXTUAL_FORM_CAP(n)) {
			printf("  FAIL form status %d on assembled text of %u bytes\n  ", (int)st, n);
			show(b, n);
			fails++;
			return;
		}
		rq = (struct kgenome_textual_form_req){ .in = fbuf, .n = w1, .lang = PSH, .out = fbuf2, .cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
		kgenome_textual_form(&rq, &rs);
		w2 = rs.n_out;
		if (w2 != w1 || memcmp(fbuf, fbuf2, w1)) {
			printf("  FAIL the form is not its own form, assembled text of %u bytes:\n  ", n);
			show(b, n);
			fails++;
			return;
		}
	}
}

static void properties(void)
{
	/* the alphabets: the delimiters as single bytes (the three-byte quotes are bytes too, drawn singly and so sometimes
	 * whole), then the pieces above */
	static const char a1[] = "#'\"`$(){}@<>\n\r \t;|&xE\xe2\x80\x98\x99\x9a\x9b\x9c\x9d\x9e";
	static const char a2[] = "'@\"\n$(){#<>";
	static const char a3[] = "@'\n\"`#$(";

	partition_for(PSH, a1, 2026u);
	partition_for(PSH, a2, 77u);
	partition_for(PSH, a3, 31u);
	form_property_for(PSH, a1, 99u);
	form_property_for(PSH, a2, 5u);
	form_property_for(PSH, a3, 8u);
	pieces_property(4242u);
}

/* Takes every span of a long text and keeps only what the partition needs. */
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

static void whole_run(const uint8_t *in, uint32_t n, struct whole *c, struct kgenome_textual_lex_res *rs,
		      enum kgenome_textual_status *st)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = PSH, .sink = whole_sink, .user = c };

	*c = (struct whole){ 0 };
	*st = kgenome_textual_lex(&rq, rs);
}

static void hostile(void)
{
	static const char sample[] =
		"#!/usr/bin/pwsh\n$x = \"a $(\"b\" + 'c') ${d e} `\" \"\" \" # c\n@'\nh\n  '@\n'@ | iex <# k #> \xe2\x80\x98q\xe2\x80\x99\r\n"
		"@\"\n$(1 +\n2)\n\"@; [Convert]::FromBase64String('YQ==')`\n$y#z\n";
	static struct rend r;
	uint32_t n;

	/* cut at every length the partition holds */
	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, PSH);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* NUL bytes everywhere: they are code bytes, in a string a byte of it */
	{
		static char z[sizeof sample];
		uint32_t i;

		for (i = 0; i < sizeof sample - 1u; i += 7u) {
			memcpy(z, sample, sizeof sample);
			z[i] = 0;
			lex(&r, z, sizeof sample - 1u, PSH);
			if (r.broken) {
				printf("  FAIL partition with a NUL at %u\n", i);
				fails++;
				return;
			}
		}
		lex(&r, "a\0'b\0'\0#\0", 9u, PSH);
		CK(!r.broken && r.w > 0);
	}
	/* the three line endings read the same program the same way: a comment ends before its break, the bytes of every span are the same */
	{
		static const char lf[] = "x #a\ny 'b\nc' @'\nd\n'@\n";
		static const char crlf[] = "x #a\r\ny 'b\r\nc' @'\r\nd\r\n'@\r\n";
		static const char cr[] = "x #a\ry 'b\rc' @'\rd\r'@\r";

		ps(lf, "C{x }K{#a}C{\ny }S{'b\nc'}C{ }S#{@'\nd\n'@}C{\n}");
		ps(crlf, "C{x }K{#a}C{\r\ny }S{'b\r\nc'}C{ }S#{@'\r\nd\r\n'@}C{\r\n}");
		ps(cr, "C{x }K{#a}C{\ry }S{'b\rc'}C{ }S#{@'\rd\r'@}C{\r}");
	}
	/* nesting past the bound: the string is open to the end, never a loop and never a deep stack */
	{
		static char deep[16384];
		uint32_t w = 0, i;
		struct whole c;
		struct kgenome_textual_lex_res rs;
		enum kgenome_textual_status st;

		for (i = 0; i < 300u; i++) {
			memcpy(deep + w, "\"$(", 3);
			w += 3;
		}
		memcpy(deep + w, "x", 1);
		w++;
		for (i = 0; i < 300u; i++) {
			memcpy(deep + w, ")\"", 2);
			w += 2;
		}
		whole_run((const uint8_t *)deep, w, &c, &rs, &st);
		CK(c.next == w && !c.broken && st == KGENOME_TEXTUAL_OPEN);
		/* within the bound the same shape closes: one string */
		for (w = 0, i = 0; i < 20u; i++, w += 3)
			memcpy(deep + w, "\"$(", 3);
		deep[w++] = 'x';
		for (i = 0; i < 20u; i++, w += 2)
			memcpy(deep + w, ")\"", 2);
		lex(&r, deep, w, PSH);
		CK(!r.broken && r.out[0] == 'S' && r.out[1] == '*' && r.out[2] == '{' && !strchr(r.out, 'C'));
	}
	/* LINEAR WORK. Each unit is repeated to 600 KB and left open or closed in the way that would cost a lexer
	 * that rescans: a name that never closes, a sub-expression that never closes, a string inside one, a here-string
	 * opener per line, comment openers, a closer on every line. */
	{
		static const char *const unit[] = { "${ ", "\"$(\n", "\"$(\"\n", "\"${\n", "@'\n", "@\"\n$(\n", "<# ", "#\n", "`", "'",
						    "\"", "@'\n'@\n", "$(", "\"$(1 \"", "a#", "$x#", "@'\nx\n  '@ ", "\"`$(" };
		static uint8_t big[600u * 1024u];
		clock_t t0 = clock();
		uint32_t k;

		for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
			size_t ul = strlen(unit[k]);
			uint32_t w = 0;
			struct whole c;
			struct kgenome_textual_lex_res rs;
			enum kgenome_textual_status st;

			while (w + ul <= sizeof big) {
				memcpy(big + w, unit[k], ul);
				w += (uint32_t)ul;
			}
			whole_run(big, w, &c, &rs, &st);
			CK((st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c.next == w && !c.broken && rs.n_span == c.n);
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 30.0);
	}
	/* the form of a huge unclosed literal fits its cap */
	{
		static uint8_t big[300u * 1024u], out[KGENOME_TEXTUAL_FORM_CAP(300u * 1024u)];
		struct kgenome_textual_form_req rq = { .in = big, .n = sizeof big, .lang = PSH, .out = out, .cap = sizeof out };
		struct kgenome_textual_form_res rs;
		uint32_t i;

		for (i = 0; i < sizeof big; i++)
			big[i] = (uint8_t)"'a\"`$(x \n"[i % 9u];
		CK(kgenome_textual_form(&rq, &rs) != KGENOME_TEXTUAL_SMALL && rs.n_out <= KGENOME_TEXTUAL_FORM_CAP(sizeof big));
	}
}

int main(void)
{
	comments();
	singles();
	doubles();
	heres();
	code();
	forms();
	values();
	decoders();
	generator();
	properties();
	hostile();
	printf("textual psh: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
