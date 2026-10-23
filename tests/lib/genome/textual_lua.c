/*
 * genome / textual_lua - the lua lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED, and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS, one per rule with the neighbour it could be confused for. A case is the text and the one line it
 *       must come out as (kind letter, bytes in braces; S* = a backslash is an escape in it, S! = not closed, K! = a
 *       comment not closed - see textual_check.h). `lu(...)` is a case lua 5.4 lexes
 *       without a lexical error: the scratch run of the report writes each to disk (-DLUA_DUMP_DIR) and `luac -p` reads it,
 *       and none may say unfinished string, malformed number or invalid escape - most are FRAGMENTS and stop at the parser,
 *       which proves little about where a token ends, so the strong evidence is (b); `lux(...)` is a case that is not a program or
 *       holds an unclosed literal, and the comment at the call says why. The form cases (`fm`) are programs: the listing
 *       `luac -l` of each is compared with the listing of its form.
 *   (b) A GENERATOR of lua programs (textual_lua_gen.h) with the spans it knows, the form of each, and the form's idempotence.
 *   (c) THE PARTITION and the idempotence of the form on random text from a lua alphabet and from any byte, a text cut at
 *       every length, and hostile texts (a huge unclosed literal of every kind, a quadratic-looking closer, NUL bytes, every
 *       line ending) read in time linear in them.
 *   (d) FORM known answers, the VALUE of literals through kgenome_textual_value, and that lua has NO decoder: a hook is never asked.
 *
 * Everything goes through <kgenome.h> and nothing else: a test of a language is a test of the API.
 */

#include "textual_check.h"

#include <time.h>

#define LUA KGENOME_TEXTUAL_LANG_LUA

#ifdef LUA_DUMP_DIR
static void dump(const char *tag, const char *src)
{
	static unsigned k;
	char name[256];
	FILE *f;

	snprintf(name, sizeof name, LUA_DUMP_DIR "/%s%04u.lua", tag, k++);
	f = fopen(name, "wb");
	if (f) {
		fwrite(src, 1, strlen(src), f);
		fclose(f);
	}
}
#else
#define dump(tag, src) ((void)0)
#endif

static void lu(const char *src, const char *want)
{
	dump("lex", src);
	expect_lang(LUA, src, want);
}

/* Not confirmed by the interpreter (not a program, or a literal that is not closed): the reason is the comment at the call. */
static void lux(const char *src, const char *want)
{
	expect_lang(LUA, src, want);
}

static void comments(void)
{
	lu("x = 1 -- c\ny = 2", "C{x = 1 }K{-- c}C{\ny = 2}");
	lu("--c", "K{--c}");
	lu("--", "K{--}");
	lu("x--\ny", "C{x}K{--}C{\ny}");
	/* a long comment, of any level; the closer is the one of the same level, and shorter or longer runs are text */
	lu("--[[a\nb]] x", "K{--[[a\nb]]}C{ x}");
	lu("--[==[a]]b]=]c]===]d]==] x", "K{--[==[a]]b]=]c]===]d]==]}C{ x}");
	lu("--[=[]=]x", "K{--[=[]=]}C{x}");
	lu("--[[]]--[[ ]]z", "K{--[[]]}K{--[[ ]]}C{z}");
	lu("--[[ a ]]]]", "K{--[[ a ]]}C{]]}");
	lu("--[==[ ]]==]==]", "K{--[==[ ]]==]}C{==]}");
	/* "--[" with no second bracket after the "="s is a line comment: the bytes after it are text to the end of the line */
	lu("--[ x\ny", "K{--[ x}C{\ny}");
	lu("--[=x\ny", "K{--[=x}C{\ny}");
	lu("--[==\ny", "K{--[==}C{\ny}");
	lu("--[=[x\n]]\n]=]y", "K{--[=[x\n]]\n]=]}C{y}");
	lu("---[[ x\ny]]", "K{---[[ x}C{\ny]]}");
	lu("--- [[x]] y", "K{--- [[x]] y}");
	/* not closed: to the end of the text, flagged */
	lux("--[[ x", "K!{--[[ x}");
	lux("--[==[ x ]=] ]]", "K!{--[==[ x ]=] ]]}");
	lux("--[[", "K!{--[[}");
	lux("--[=[]", "K!{--[=[]}");
	/* a line comment ends at any line break; a pair of two kinds is one break */
	lu("x--a\r\ny", "C{x}K{--a}C{\r\ny}");
	lu("x--a\ry", "C{x}K{--a}C{\ry}");
	lu("x--a\n\ry", "C{x}K{--a}C{\n\ry}");
	/* a comment marker in a string is the string's, and a quote or a bracket in a comment is the comment's */
	lu("x = '--' --[[ ']] y = \"--\"", "C{x = }S*{'--'}C{ }K{--[[ ']]}C{ y = }S*{\"--\"}");
	lu("-- ' \" [[ \nx = 1", "K{-- ' \" [[ }C{\nx = 1}");
	lu("x = [[ -- ]] -- [[\ny]]", "C{x = }S{[[ -- ]]}C{ }K{-- [[}C{\ny]]}");
	/* a minus and then a comment: "- -x" is two minuses, "--x" is a comment */
	lu("a = b - -c", "C{a = b - -c}");
	lu("a = b --c", "C{a = b }K{--c}");
	lu("a = b - --c\n 1", "C{a = b - }K{--c}C{\n 1}");
	/* the interpreter line: "#!" at byte 0 and nowhere else */
	lux("#!/usr/bin/lua\nx = 1", "K{#!/usr/bin/lua}C{\nx = 1}");
	lux("#!", "K{#!}");
	/* the line ends at an LF only: it is the loader's, and a CR-only file after "#!" is all comment to lua 5.4 */
	lux("#!x\r\ny", "K{#!x\r}C{\ny}");
	lux("#!x\ry\rz", "K{#!x\ry\rz}");
	lux("#!x\n\ry", "K{#!x}C{\n\ry}");
	lux("#x\ny", "C{#x\ny}");
	lux(" #!x", "C{ #!x}");
	lux("\n#!x", "C{\n#!x}");
	lux("x\n#!y", "C{x\n#!y}");
	lu("#t", "C{#t}");
}

static void strings(void)
{
	lu("x = 'a' .. \"b\"", "C{x = }S*{'a'}C{ .. }S*{\"b\"}");
	lu("x = '' .. \"\"", "C{x = }S*{''}C{ .. }S*{\"\"}");
	/* the other quote is a byte of the string, and the own quote escaped is not its end */
	lu("'a\"b' \"a'b\" 'a\\'b' \"a\\\"b\" x", "S*{'a\"b'}C{ }S*{\"a'b\"}C{ }S*{'a\\'b'}C{ }S*{\"a\\\"b\"}C{ x}");
	lu("'\\\\' x", "S*{'\\\\'}C{ x}");
	lu("'\\\\\\'' x", "S*{'\\\\\\''}C{ x}");
	/* an escaped break continues the string, whichever break it is; the pair of two kinds is ONE break, so the
	 * second byte is not a break that ends the string */
	lu("x='a\\\nb' y", "C{x=}S*{'a\\\nb'}C{ y}");
	lu("x='a\\\r\nb' y", "C{x=}S*{'a\\\r\nb'}C{ y}");
	lu("x='a\\\n\rb' y", "C{x=}S*{'a\\\n\rb'}C{ y}");
	lu("x='a\\\rb' y", "C{x=}S*{'a\\\rb'}C{ y}");
	lu("x=\"a\\\n\\\nb\" y", "C{x=}S*{\"a\\\n\\\nb\"}C{ y}");
	/* \z skips white space of every kind, line breaks included; a break after it is not an end of the string */
	lu("x='a\\z  \n \t\r\n b' y", "C{x=}S*{'a\\z  \n \t\r\n b'}C{ y}");
	lu("x='a\\z\f\v b' y", "C{x=}S*{'a\\z\f\v b'}C{ y}");
	lu("x='a\\zb' y", "C{x=}S*{'a\\zb'}C{ y}");
	/* the escapes are the string's: the lexer reads the pair, not the letters */
	lu("'\\n\\x41\\65\\u{48}\\z \\0'", "S*{'\\n\\x41\\65\\u{48}\\z \\0'}");
	lu("'\\x27' \"\\x22\" x", "S*{'\\x27'}C{ }S*{\"\\x22\"}C{ x}");
	/* not closed: a one-line string ends at its line, whichever break */
	lux("'abc", "S*!{'abc}");
	lux("'abc\ndef'", "S*!{'abc}C{\ndef}S*!{'}");
	lux("'abc\r\ndef", "S*!{'abc}C{\r\ndef}");
	lux("'abc\rdef", "S*!{'abc}C{\rdef}");
	lux("'abc\n\rdef", "S*!{'abc}C{\n\rdef}");
	lux("\"", "S*!{\"}");
	lux("'a\\", "S*!{'a\\}");
	lux("'a\\z", "S*!{'a\\z}");
	lux("'a\\z \n ", "S*!{'a\\z \n }");
	lux("'a\\\n", "S*!{'a\\\n}");
	/* long strings: any level, the closer of the same level, no escape */
	lu("[[a]] [=[b]] ]=] [==[c]=]]==] x", "S{[[a]]}C{ }S{[=[b]] ]=]}C{ }S{[==[c]=]]==]}C{ x}");
	lu("x = [[\nabc\n]] y", "C{x = }S{[[\nabc\n]]}C{ y}");
	lu("x = [[\\]] y", "C{x = }S{[[\\]]}C{ y}");
	lu("x = [[ ' \" -- ]] y", "C{x = }S{[[ ' \" -- ]]}C{ y}");
	lu("[[]]x[=[]=]y[==[]==]", "S{[[]]}C{x}S{[=[]=]}C{y}S{[==[]==]}");
	lu("[[a]]]]", "S{[[a]]}C{]]}");
	lu("[=[a]==]]=]", "S{[=[a]==]]=]}");
	lu("[==[a]=]]===]]==]", "S{[==[a]=]]===]]==]}");
	lu("[=[ ]]]=]", "S{[=[ ]]]=]}");
	lu("[[\r\n]] [[\n\r]] [[\r]]", "S{[[\r\n]]}C{ }S{[[\n\r]]}C{ }S{[[\r]]}");
	lux("[[abc", "S!{[[abc}");
	lux("[==[abc]=]]]", "S!{[==[abc]=]]]}");
	lux("[=[", "S!{[=[}");
	/* "[" "=" "..." that is not an opener is code: indexing, a comparison, a table field */
	lu("a[b] = c[ [[x]] ]", "C{a[b] = c[ }S{[[x]]}C{ ]}");
	lux("a[=b [== c", "C{a[=b [== c}");
	lux("[=", "C{[=}");
	lux("[", "C{[}");
	lux("[==", "C{[==}");
	lu("t[[x]]", "C{t}S{[[x]]}");
	lu("t{[1]=2,[ [[k]] ]=3}", "C{t{[1]=2,[ }S{[[k]]}C{ ]=3}}");
	lu("f[[x]]..f[=[y]=]", "C{f}S{[[x]]}C{..f}S{[=[y]=]}");
}

static void numbers(void)
{

	/* llex.c read_numeral takes every hexadecimal digit of a number, whatever its base, then an exponent mark and ITS sign: `0fe--x` is the number "0fe-" and "-x" (a malformed number to the
	 * interpreter, and so no program: lux), and not "0fe" and a comment - which is what a scanner that stops at the first letter that is no decimal digit makes of it (mutants.out: the digit test
	 * of the numeral scanner replaced by a decimal one survived every case of this file). [Unverified] against lua 5.4: none on this machine; read from llex.c. */
	lux("0fe--x", "C{0fe--x}");
	lux("0fe+x", "C{0fe+x}");
	lux("0ae--x\n", "C{0ae--x\n}");
	/* a number is code, but it decides where a comment begins: a hex digit "e" is not an exponent, "p" is, and the sign
	 * after an exponent is part of the number */
	lu("x=0xe--c\n", "C{x=0xe}K{--c}C{\n}");
	lu("x=0xe-1", "C{x=0xe-1}");
	lu("x=1e-5--c\n", "C{x=1e-5}K{--c}C{\n}");
	lu("x=1E+5--[[c]]y", "C{x=1E+5}K{--[[c]]}C{y}");
	lu("x=0x1p-4--c\n", "C{x=0x1p-4}K{--c}C{\n}");
	lu("x=0x.1p-3--c", "C{x=0x.1p-3}K{--c}");
	lu("x=3.--c", "C{x=3.}K{--c}");
	lu("x=.5--c", "C{x=.5}K{--c}");
	lu("x=5-- c", "C{x=5}K{-- c}");
	lu("x=0xA.8p1--c", "C{x=0xA.8p1}K{--c}");
	lu("x=0xep1--c", "C{x=0xep1}K{--c}");
	/* the sign after "e" in a number that is not an exponent: a name ends in e, a number does not begin in it */
	lu("x=e--c", "C{x=e}K{--c}");
	lu("x=x1e--c", "C{x=x1e}K{--c}");
	lu("x=t0x--c", "C{x=t0x}K{--c}");
	lu("x=a-e-1", "C{x=a-e-1}");
	lu("x=a..5--c", "C{x=a..5}K{--c}");
	lu("x=a.b--c", "C{x=a.b}K{--c}");
	lu("x=a..b..'c'", "C{x=a..b..}S*{'c'}");
	/* an exponent sign then a dash is not a program: "1e-" is one malformed numeral, and "-1" what follows it */
	lux("x=1e--1", "C{x=1e--1}");
	lux("x=1..2", "C{x=1..2}");
	lux("x=1e5\"a\"", "C{x=1e5}S*{\"a\"}");
	lux("x=0x\"a\"", "C{x=0x}S*{\"a\"}");
}

static void line_endings(void)
{
	/* each program in the four line endings: nothing but the code between them changes */
	lu("a=1\nb='x'\n--c\nd=[[y\nz]]\n", "C{a=1\nb=}S*{'x'}C{\n}K{--c}C{\nd=}S{[[y\nz]]}C{\n}");
	lu("a=1\r\nb='x'\r\n--c\r\nd=[[y\r\nz]]\r\n", "C{a=1\r\nb=}S*{'x'}C{\r\n}K{--c}C{\r\nd=}S{[[y\r\nz]]}C{\r\n}");
	lu("a=1\rb='x'\r--c\rd=[[y\rz]]\r", "C{a=1\rb=}S*{'x'}C{\r}K{--c}C{\rd=}S{[[y\rz]]}C{\r}");
	lu("a=1\n\rb='x'\n\r--c\n\rd=[[y\n\rz]]\n\r", "C{a=1\n\rb=}S*{'x'}C{\n\r}K{--c}C{\n\rd=}S{[[y\n\rz]]}C{\n\r}");
	/* NUL bytes are bytes: a string, a comment and a long string with one in them are still one span each */
	{
		static const char nul[] = "x='a\0b' --c\0d\ny=[[e\0f]]";
		static struct rend r;

		lex(&r, nul, sizeof nul - 1u, LUA);
		CK(!r.broken && strchr(r.out, 'S') && strchr(r.out, 'K'));
		CK(r.out[0] == 'C' && strstr(r.out, "S*{'a") && strstr(r.out, "K{--c") && strstr(r.out, "S{[[e"));
	}
}

#include "textual_lua_gen.h"

/* ---- (d) the form ---- */

static void fm(const char *src, const char *want)
{
	dump("form_in", src);
	dump("form_out", want);
	form_lang(LUA, src, want);
}

/* A form of text that is not a program, or whose program is not the form's (a closed-up pair that is two tokens either way). */
static void fmx(const char *src, const char *want)
{
	form_lang(LUA, src, want);
}

static void forms(void)
{
	fm("", "");
	/* indentation goes, a line break stays one (a statement may end there), blank lines, comments and the blanks in a line go */
	fm("if x then\n    y = 1  -- c\n\n\n    z = 2\nend\n", "if x then\ny=1\nz=2\nend");
	fm("local function f(a, b)\n  return a + b\nend\n", "local function f(a,b)\nreturn a+b\nend");
	fm("-- only\n", "");
	fm("x = a  -- c1\n-- c2\n\n--[[ c3 ]]\ny = 2", "x=a\ny=2");
	/* a name next to a name keeps its space; a comment is a gap, and separates two names */
	fm("x = a and b or c", "x=a and b or c");
	fm("a --[[c]] b", "a b");
	fm("a--[[c]]=b", "a=b");
	fm("local a --c\nb = 1", "local a\nb=1");
	/* what closing up would change keeps its space: "- -" is not "--" (a comment), ". ." is not "..", "= =" is "==", "1 .." is
	 * not "1..", "[ [" and "= [" would open a long bracket, "/ /" "< <" "> >" ": :" are two bytes of one token */
	fm("x = b - -c", "x=b- -c");
	fm("x = - - b", "x=- -b");
	fm("x = a .. 1 .. 2; y = s .. 1 .. t .. 'u'; z = 0xe .. 0xe", "x=a ..1 ..2;y=s..1 .. t..'u';z=0xe ..0xe");
	fm("x = 1 .. 2", "x=1 ..2");
	fmx("x = a . . b; y = 5. until", "x=a . . b;y=5. until");
	fmx("x = a = = b; y = a ~ = b; z = a < = b; w = a > = b", "x=a= =b;y=a~ =b;z=a< =b;w=a> =b");
	fmx("x = a / / b; y = a < < b; z = a > > b; ::a: :b", "x=a/ /b;y=a< <b;z=a> >b;::a: :b");
	fm("x = a // b; y = a << b; z = a >> b; ::a::", "x=a//b;y=a<<b;z=a>>b;::a::");
	fm("t [ 1 ] = u [ [[x]] ]", "t[1]=u[ [[x]]]");
	fmx("a [ = b", "a[ =b");
	fm("t = { [ 1 ] = 2 , [ 'k' ] = 3 ; 4 }", "t={[1]=2,['k']=3;4}");
	fm("x = [[a]]", "x= [[a]]");
	fm("print ( 'a' , \"b\" )", "print('a',\"b\")");
	fm("f 'x'; g [[y]]; h { 1 }", "f'x';g[[y]];h{1}");
	/* the long forms of a comment, a string, a call keep what they are */
	fm("x = [==[ a\n   b ]==] -- c", "x= [==[ a\n   b ]==]");
	fm("x = '  a  ' -- c\ny = \"  \"", "x='  a  '\ny=\"  \"");
	/* the interpreter line is kept; one that is not at the start is code (a "#" is the length operator) */
	fmx("#!/usr/bin/lua\nx = 1 -- c", "#!/usr/bin/lua\nx=1");
	fm("x = # t", "x=#t");
	/* every line ending is one line break, a lone CR included; and one that ends an unclosed string stays one */
	fm("a = 1\rb = 2\r", "a=1\nb=2");
	fm("a = 1\r\nb = 2\r\n", "a=1\nb=2");
	fm("a = 1\n\rb = 2\n\r", "a=1\nb=2");
	fm("a = 1 -- c\rb = 2", "a=1\nb=2");
	fmx("x = 'abc", "x='abc");
	fmx("x = 'abc\rdef", "x='abc\ndef");
	fmx("x =  [[abc", "x= [[abc");
	fmx("x =  --[[abc", "x=--[[abc");
}

/* The spelled-out bytes of a lua string, written as themselves: exactly what lua 5.4 reads as an escape. */
static void unescapes(void)
{
	/* the names a script spells so that no marker finds them: hex, decimal and \u{} */
	fm("x = \"\\x65\\x76\\x61\\x6c\" .. '\\65\\66' .. \"\\u{48}\\u{0069}\"", "x=\"eval\"..'AB'..\"Hi\"");
	fm("x = \"\\x41B\\x4a\\x4A\"", "x=\"ABJJ\"");
	/* not a byte that is printable ASCII and not a quote, a backslash or a closing brace */
	fm("x = '\\x0a\\x7f\\x01\\2\\255' .. '\\x22\\x27\\x5c\\x7d\\u{7d}\\u{80}\\u{7FFFFFFF}'",
	   "x='\\x0a\\x7f\\x01\\2\\255'..'\\x22\\x27\\x5c\\x7d\\u{7d}\\u{80}\\u{7FFFFFFF}'");
	/* lua's escapes are not python's: no \u0041 (it is an error, kept), no octal, a decimal one is up to 255 */
	fmx("x = '\\u0041\\122\\256\\q'", "x='\\u0041z\\256\\q'");
	/* a backslash and the byte after it are a pair: \\x41 is a backslash and the text x41 */
	fm("x = '\\\\x41' .. '\\\\\\x41'", "x='\\\\x41'..'\\\\A'");
	/* an escape still waiting for digits does not take the next one's: "\0" "\x31" is not "\01" */
	fm("x = '\\0\\x31' .. '\\9\\50' .. '\\0\\x6d'", "x='\\0\\x31'..'\\9\\50'..'\\0m'");
	fm("x = '\\1' .. '2'; y = '\\x41' .. 'a'; z = '\\012\\x31'", "x='\\1'..'2';y='A'..'a';z='\\0121'");
	fmx("x = '\\x4\\x61' .. '\\x4\\x67'", "x='\\x4\\x61'..'\\x4g'");
	fmx("x = '\\u{4\\x31}' .. '\\u{4\\x67}' .. '\\u{4\\x7d}'", "x='\\u{4\\x31}'..'\\u{4g}'..'\\u{4\\x7d}'");
	fmx("x = '\\xg\\x61' .. '\\x\\x41'", "x='\\xga'..'\\x\\x41'");
	/* \z skips white space after it, so no blank is written there: "\z\x20a" is "a" and not " a" read after the skip */
	fm("x = '\\z\\x20a' .. '\\z\\x41' .. 'b\\x20c'", "x='\\z\\x20a'..'\\zA'..'b c'");
	fm("x = '\\z  \n  \\x20a'", "x='\\z  \n  \\x20a'");
	/* a line break after a backslash is kept as typed */
	fm("x = 'a\\\nb\\x41'", "x='a\\\nbA'");
	fm("x = 'a\\\r\nb\\x41' .. 'c\\\n\rd'", "x='a\\\r\nbA'..'c\\\n\rd'");
	/* a long string has no escape */
	fm("x = [[\\x41\\65]] .. [=[\\u{41}]=]", "x= [[\\x41\\65]]..[=[\\u{41}]=]");
	/* a comment holding an escape is a comment, and goes */
	fm("x = 1 -- '\\x41'", "x=1");
}

/* THE VALUE of a literal, through the API: the lib decodes what the text says, never a value with a hole in it. */
static void val(const char *lit, uint32_t open, uint32_t close, uint8_t flags, const char *want, uint32_t want_n)
{
	uint8_t out[256];
	struct kgenome_textual_value_req rq = { .lang = LUA, .lit = (const uint8_t *)lit, .len = (uint32_t)strlen(lit),
						.open_len = open, .close_len = close, .flags = flags, .out = out, .cap = sizeof out };
	struct kgenome_textual_value_res rs;
	enum kgenome_textual_status st = kgenome_textual_value(&rq, &rs);

	if (!want) {
		if (st != KGENOME_TEXTUAL_NO_VALUE || rs.n_out) {
			printf("  FAIL value of %s: status %d, wanted no value\n", lit, (int)st);
			fails++;
		}
		return;
	}
	if (st != KGENOME_TEXTUAL_OK || rs.n_out != want_n || memcmp(out, want, want_n)) {
		printf("  FAIL value of %s: status %d, %u bytes, wanted %u\n", lit, (int)st, rs.n_out, want_n);
		fails++;
	}
}

#define V(lit, open, close, want) val(lit, open, close, 0, want, (uint32_t)sizeof(want) - 1u)
#define NOV(lit, open, close) val(lit, open, close, 0, NULL, 0)

static void values(void)
{
	V("'a\\nb'", 1, 1, "a\nb");
	V("\"\\a\\b\\f\\n\\r\\t\\v\\\\\\\"\\'\"", 1, 1, "\a\b\f\n\r\t\v\\\"'");
	V("\"\\x41\\65\\u{48}\\z   \n  x\"", 1, 1, "AAHx");
	V("'\\0123'", 1, 1, "\f3");
	V("'\\u{0}\\0\\x00'", 1, 1, "\0\0\0");
	V("'\\255\\xFf'", 1, 1, "\xff\xff");
	/* \u{} is utf-8, long form to six bytes, and has no surrogate check */
	V("'\\u{48}\\u{e9}\\u{20AC}\\u{10FFFF}'", 1, 1, "H\xc3\xa9\xe2\x82\xac\xf4\x8f\xbf\xbf");
	V("'\\u{7FFFFFFF}'", 1, 1, "\xfd\xbf\xbf\xbf\xbf\xbf");
	V("'\\u{D800}'", 1, 1, "\xed\xa0\x80");
	/* a backslash and a line break is "\n", the pair of two kinds being one */
	V("'a\\\nb'", 1, 1, "a\nb");
	V("'a\\\r\nb'", 1, 1, "a\nb");
	V("'a\\\n\rb'", 1, 1, "a\nb");
	V("'a\\\rb'", 1, 1, "a\nb");
	V("'a\\\n\nb'", 1, 1, "a\n\nb");
	V("'a\\z'", 1, 1, "a");
	/* what lua 5.4 refuses has no value: an unknown escape, a short \x, a decimal above 255, a \u without braces or too large */
	NOV("'\\q'", 1, 1);
	NOV("'\\x4'", 1, 1);
	NOV("'\\xg1'", 1, 1);
	NOV("'\\256'", 1, 1);
	NOV("'\\u0041'", 1, 1);
	NOV("'\\u{}'", 1, 1);
	NOV("'\\u{41'", 1, 1);
	NOV("'\\u{80000000}'", 1, 1);
	NOV("'\\u{FFFFFFFFF}'", 1, 1);
	/* long strings: the first break is skipped, every break is "\n", nothing is an escape */
	V("[[abc]]", 2, 2, "abc");
	V("[[\nabc]]", 2, 2, "abc");
	V("[[\r\nx\r\ny]]", 2, 2, "x\ny");
	V("[[\n\rx\n\ry]]", 2, 2, "x\ny");
	V("[[\rx\ry\r\r]]", 2, 2, "x\ny\n\n");
	V("[[\n\nx]]", 2, 2, "\nx");
	V("[==[\r\n]=]x]==]", 4, 4, "]=]x");
	V("[=[a\\n\\x41]=]", 3, 3, "a\\n\\x41");
	V("[[]]", 2, 2, "");
	/* a literal that was not closed has none */
	val("'abc", 1, 0, KGENOME_TEXTUAL_F_OPEN, NULL, 0);
	val("[[abc", 2, 0, KGENOME_TEXTUAL_F_OPEN, NULL, 0);
}

/* LUA HAS NO DECODER BY NAME: load and loadstring take text and run it, so there is no chain and the hook is never asked. */
static uint32_t hook_calls;

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
		       const uint8_t **out, uint32_t *out_len)
{
	(void)user;
	(void)chain;
	(void)n_chain;
	(void)in;
	(void)len;
	(void)out;
	(void)out_len;
	hook_calls++;
	return 0;
}

static void decoders(void)
{
	static const char *const src[] = {
		"load('x = 1')()", "loadstring(\"abc\")()", "x = base64.decode('YWJj')", "x = mime.unb64('YWJj')",
		"x = ngx.decode_base64('YWJj')", "x = ('abc'):reverse()", "x = string.char(72, 105)", "x = zlib.inflate()('ab')",
		"x = load(string.reverse('abc'))",
	};
	uint8_t out[512];
	unsigned i;

	for (i = 0; i < sizeof src / sizeof src[0]; i++) {
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src[i], .n = (uint32_t)strlen(src[i]), .lang = LUA,
						       .out = out, .cap = KGENOME_TEXTUAL_FORM_CAP(strlen(src[i])) + 64u,
						       .decode = fake_decode };
		struct kgenome_textual_form_res rs;

		kgenome_textual_form(&rq, &rs);
		CK(rs.n_decoded == 0 && rs.n_refused == 0 && rs.n_folded == 0);
	}
	CK(hook_calls == 0);
}

/* ---- (c) any text at all ---- */

static void properties(void)
{
	/* the spans partition the text, and the form of a form is itself, on text drawn from what changes the lexer's mind:
	 * quotes, a backslash, brackets, "=", dashes, dots, the letters of a number, line breaks of all kinds */
	partition_for(LUA, "-[]=\"'\\\n\r\t\f .#!{}()zxeEpP0129afAF,;:<>~+*/", 2024u);
	partition_for(LUA, "-[]=\n'\\", 77u);
	partition_for(LUA, "--[=]]\n\r\"", 31u);
	form_property_for(LUA, "-[]=\"'\\\n\r\t\f .#!{}()zxeEpP0129afAF,;:<>~+*/", 99u);
	form_property_for(LUA, "-[]=\n'\\x41u{}z \r", 5u);
	form_property_for(LUA, "--[=]\n\"' a1", 6u);
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

/* The spans partition a text cut at every length, and a hostile one is read in time proportional to it. */
static void hostile(void)
{
	static const char sample[] =
		"#!/usr/bin/lua\nx = '\\z \n a\\\r\nb' .. [==[t\n]=]]]==] --[=[ c\n]] ]=] y = 0xe--c\nz = 1e-5 --d\r\nw = [[\n\r]]\r";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, LUA);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* LINEAR WORK. Each unit repeated to 600 KB is a text whose literal never closes, or whose closer is searched for among
	 * runs that are almost one. A lexer that read to the end again for every opener or every "]" would do 10^11 steps here. */
	{
		static const char *const unit[] = { "'\\z\n", "\"a\\\n", "[==[", "--[=[", "]=]=]=", "[=[]==]", "[[ ]=]", "--[==[ ]]=",
						    "]]]]]]]]", "[=", "[=[=[=[=", "--[\n", "\\z \n\\z ", "x'\\\n'", "1e-", "0x1p-.", "-[[" };
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
			rq = (struct kgenome_textual_lex_req){ .in = big, .n = w, .lang = LUA, .sink = whole_sink, .user = &c };
			st = kgenome_textual_lex(&rq, &rs);
			CK((st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c.next == w && !c.broken && rs.n_span == c.n);
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
	}
	/* one huge unclosed literal of each kind is one span flagged open, and a lot of NUL bytes is only bytes */
	{
		static uint8_t huge[1u << 20];
		uint32_t k;
		static const char *const open[] = { "'", "\"", "[[", "[==[", "--[[", "--[=[", "'\\z" };

		for (k = 0; k < sizeof open / sizeof open[0]; k++) {
			size_t ol = strlen(open[k]);
			struct whole c = { 0 };
			struct kgenome_textual_lex_req rq;
			struct kgenome_textual_lex_res rs;

			memcpy(huge, open[k], ol);
			memset(huge + ol, k % 2u ? 'x' : 0, sizeof huge - ol);
			rq = (struct kgenome_textual_lex_req){ .in = huge, .n = sizeof huge, .lang = LUA, .sink = whole_sink, .user = &c };
			CK(kgenome_textual_lex(&rq, &rs) == KGENOME_TEXTUAL_OPEN && c.next == sizeof huge && !c.broken && rs.n_span == 1u);
		}
	}
}

int main(void)
{
	comments();
	strings();
	numbers();
	line_endings();
	generator();
	forms();
	unescapes();
	values();
	decoders();
	properties();
	hostile();
	if (fails) {
		printf("FAIL: %d\n", fails);
		return 1;
	}
	printf("textual_lua: ok\n");
	return 0;
}
