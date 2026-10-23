#ifndef KGENOME_TEXTUAL_H
#define KGENOME_TEXTUAL_H

/*
 * textual.h - the analysis of text that has a grammar: scripts, and later other
 * languages written as text. The part's one public header.
 *
 * It is the API only. What is specific to a language lives in the directory named for it
 * (php/), reached through one table (textual_lang_table.c) and nowhere else, so a
 * language is added by a directory and a row and nothing in this directory changes.
 *
 * LEX. One pass over the bytes, no allocation, no recursion past a depth of the lexer's
 * own: the result is a stream of spans (textual_span.h) given to a sink, so nothing here
 * holds more memory than a span and the caller decides what to keep. A text is lexed as it
 * is typed. Nothing is decoded, joined, renamed or evaluated; that is what the passes
 * built on the spans are for.
 *
 * THERE IS NO BUDGET ARGUMENT because the work is one read of the input and the output is
 * delivered, not stored. Where a lexer must look ahead - a group or a hole that may not
 * close - the look is bounded by an allowance that follows the text, and a bound that
 * fires is counted in kgenome_textual_lex_res.n_bound; a nesting past a lexer's own depth
 * is read open to the end of the text (the span carries F_OPEN, counted in n_open).
 */

#include <stdint.h>
#include <string.h>

#include "textual_span.h"
#include "textual_status.h"

/* The languages this build has a lexer for. Its own numbering, not the engine's. */
enum kgenome_textual_lang_id {
	KGENOME_TEXTUAL_LANG_NONE = 0,
	KGENOME_TEXTUAL_LANG_PHP,
	KGENOME_TEXTUAL_LANG_SH,        /* posix shell and what is close enough to it: bash, ksh, busybox ash */
	KGENOME_TEXTUAL_LANG_JS,        /* javascript, and jscript */
	KGENOME_TEXTUAL_LANG_VBS,       /* vbscript: a .vbs file */
	KGENOME_TEXTUAL_LANG_ASP,       /* classic asp: a page with vbscript (or jscript) in <% %> */
	KGENOME_TEXTUAL_LANG_JSP,       /* java server pages */
	KGENOME_TEXTUAL_LANG_ASPX,      /* asp.net: c# (or vb) in <% %> and <script runat="server"> */
	KGENOME_TEXTUAL_LANG_PY,        /* python */
	KGENOME_TEXTUAL_LANG_PERL,        /* perl */
	KGENOME_TEXTUAL_LANG_RUBY,        /* ruby */
	KGENOME_TEXTUAL_LANG_LUA,        /* lua */
	KGENOME_TEXTUAL_LANG_TCL,        /* tcl */
	KGENOME_TEXTUAL_LANG_BAT,        /* windows batch (.bat, .cmd) */
	KGENOME_TEXTUAL_LANG_PSH,        /* powershell */
	KGENOME_TEXTUAL_LANG_CFM,        /* coldfusion (cfml tags and cfscript) */
	KGENOME_TEXTUAL_LANG_COUNT
};

/* Receives each span in order. Answers 0 to stop the walk. */
typedef int (*kgenome_textual_sink)(void *user, const struct kgenome_textual_span *span);

/*
 * The text is CODE OF THE LANGUAGE with nothing in front of it: what a script builds, or a payload
 * a script decodes and runs. A page is read from its markup and a language like php needs a tag to
 * leave it; a fragment has none, and is lexed from inside.
 */
#define KGENOME_TEXTUAL_FRAGMENT 0x1u

/*
 * (form only) Literals joined by the language's operator stay as typed. By default a join that ends its expression is
 * written as ONE literal, the way a decoded text is: "ev" . "al" and "eval" are the same thing to the program, and
 * only the first is a way to keep a scan from reading the name. What a caller that compares the form with the text
 * piece by piece (a test of what the form keeps) needs is this one.
 */
#define KGENOME_TEXTUAL_KEEP_JOINS 0x2u

struct kgenome_textual_lex_req {
	const uint8_t *in;
	uint32_t       n;
	uint32_t       lang;    /* enum kgenome_textual_lang_id */
	uint32_t       flags;   /* KGENOME_TEXTUAL_FRAGMENT */
	kgenome_textual_sink sink;
	void          *user;
};

struct kgenome_textual_lex_res {
	uint32_t n_span;        /* spans delivered */
	uint32_t n_open;        /* of them, how many have KGENOME_TEXTUAL_F_OPEN */
	/* How many WORK BOUNDS of the lexers fired in this walk (each lexer counts one once). The spans partition the text whatever it says; a bound is what makes a lexer read
	 * a construct that does not close as code or text instead of finding out again at every byte of it: sh's "((" and a c# string's "{" are given an allowance of the
	 * text's length and a page for the groups that failed (L3 and L5 of the lexer audit). Zero is the normal value; a caller that reports a limit reports this. */
	uint32_t n_bound;
};

/* Lex the text. The spans partition the input whatever the status; see textual_span.h. */
enum kgenome_textual_status kgenome_textual_lex(const struct kgenome_textual_lex_req *rq,
						struct kgenome_textual_lex_res *res);

/*
 * THE ISLANDS OF CODE in a text that mixes markup and code, as the language's lexer reads where code is - the one reader of a "?>" that closes, of a
 * "%>" that does, of a heredoc or a string that holds one that does not. A caller that must know where a page's code is (the engine's parsers carve
 * the object into header, body and markup by it) asks here and does not walk the bytes a second time. Delivered in order, one for each opening tag the
 * lexer found, to a sink that answers 0 to stop.
 *
 *   off, open_len   the opening tag's first byte and the length of its own bytes ("<?php" without the white space php takes after it, "<?=", "<%",
 *                   "<script ... >")
 *   end_tag, close_len  where the closing tag begins and how long its own bytes are ("?>": the line break php takes after it is not one);
 *                   the island ends at end_tag + close_len. An island that is not closed ends at end_tag with close_len 0: the end of the text, or where
 *                   the code stopped without a closing tag (the data after php's __halt_compiler is markup)
 *   closed          the closing tag was found
 * A text with no tag, or a language that has none (sh, python), has no islands. A FRAGMENT is code from its first byte and has no opening tag: its one
 * island is delivered with off 0 and open_len 0.
 */
struct kgenome_textual_island {
	uint32_t off, open_len;
	uint32_t end_tag, close_len;
	uint8_t  closed;
};
typedef int (*kgenome_textual_island_sink)(void *user, const struct kgenome_textual_island *island);
struct kgenome_textual_islands_req {
	const uint8_t *in;
	uint32_t       n;
	uint32_t       lang;    /* enum kgenome_textual_lang_id */
	uint32_t       flags;   /* KGENOME_TEXTUAL_FRAGMENT */
	kgenome_textual_island_sink sink;
	void          *user;
};
/* OK, or the status of the lex (NO_LANG, REFUSED when the sink stopped it; OPEN is a text with a construct that did not close, and the islands were delivered). */
enum kgenome_textual_status kgenome_textual_islands(const struct kgenome_textual_islands_req *rq);

/*
 * FORM. How a text was TYPED, taken out of it: the indentation, the blank lines, the comments,
 * the spacing between tokens, the line endings. Nothing the program says changes - a string is
 * copied byte for byte, markup around code is copied byte for byte - so a marker written on
 * the form matches every way of typing the program.
 *
 *   - a line break stays a line break, one of them; "\r\n" is "\n";
 *   - white space between tokens is one space where closing up would make one token of two
 *     (two name bytes, or a pair the language says glues), and nothing otherwise;
 *   - every comment goes, a trailing one too: it is a gap, which is one space where the bytes
 *     either side would glue. A comment that is not closed is kept, because what it holds
 *     is not known to be a comment;
 *   - a code block that held nothing - a tag, white space and comments - goes whole;
 *   - a "{" alone on a line joins the line above where the language says so.
 *
 * The output is never longer than KGENOME_TEXTUAL_FORM_CAP(n): the one byte the form may add is
 * the line break in front of a closing tag, and a closing tag is two bytes.
 */
#define KGENOME_TEXTUAL_FORM_CAP(n) ((uint64_t)(n) + (uint64_t)(n) / 2u + 2u)

/*
 * DECODERS A SCRIPT CALLS ON ITS OWN LITERALS. A script that hides a payload writes
 * `eval(gzinflate(base64_decode("...")))`: the literal is the payload, the name around it says
 * what it was put through, and nothing else about the call matters. The lexer finds the literal
 * and the lang row reads the names; DECODING is not this lib's - kuncoat's algorithms are reached
 * by whoever asked, through the hook below - so the lib never depends on them.
 */
enum kgenome_textual_decoder {
	KGENOME_TEXTUAL_DEC_NONE = 0,
	KGENOME_TEXTUAL_DEC_B64,        /* base64_decode */
	KGENOME_TEXTUAL_DEC_HEX,        /* hex2bin */
	KGENOME_TEXTUAL_DEC_URL,        /* urldecode */
	KGENOME_TEXTUAL_DEC_ROT13,      /* str_rot13 */
	KGENOME_TEXTUAL_DEC_REVERSE,    /* strrev */
	KGENOME_TEXTUAL_DEC_INFLATE,    /* gzinflate: raw deflate */
	KGENOME_TEXTUAL_DEC_ZLIB,       /* gzuncompress */
	KGENOME_TEXTUAL_DEC_GZIP,       /* gzdecode */
	KGENOME_TEXTUAL_DEC_RAWURL,     /* rawurldecode: urldecode that keeps "+" */
	KGENOME_TEXTUAL_DEC_HEXSTRICT,  /* hex2bin: pairs of hex digits and nothing between them (DEC_HEX skips separators) */
	/* The string functions a script builds a value with. Not decoders of a literal in front of a payload - a call
	 * chain never names them - but the same kind of thing, a function from bytes to bytes, so they share the id and
	 * the one hook that runs them (kgenome_textual_apply_fn). */
	KGENOME_TEXTUAL_DEC_REPLACE,    /* str_replace of one string: s1 -> s2 */
	KGENOME_TEXTUAL_DEC_TRANSLATE,  /* strtr of two strings: byte s1[i] -> s2[i] */
	KGENOME_TEXTUAL_DEC_SLICE,      /* substr: from k1, k2 long unless to_end */
	KGENOME_TEXTUAL_DEC_LOWER,      /* strtolower */
	KGENOME_TEXTUAL_DEC_UPPER,      /* strtoupper */
	KGENOME_TEXTUAL_DEC_UCFIRST,    /* ucfirst */
	KGENOME_TEXTUAL_DEC_LCFIRST,    /* lcfirst */
	KGENOME_TEXTUAL_DEC_TRIM,       /* trim */
	KGENOME_TEXTUAL_DEC_LTRIM,      /* ltrim */
	KGENOME_TEXTUAL_DEC_RTRIM,      /* rtrim */
	KGENOME_TEXTUAL_DEC_REPEAT,     /* the subject k1 times: python's s * n, perl's x, javascript's repeat, lua's string.rep, vbscript's String */
	/* Not a function of bytes: a byte made from a number, chr(115). The hook below does not run it (kuncoat has no algorithm that
	 * reads a number); kgenome_textual_fn_run does, so the form and the evaluator get the same byte. */
	KGENOME_TEXTUAL_DEC_CHR,        /* chr */
	/* Functions between a string and a LIST of strings (the form of kofcore/kofstrlist.h, in one buffer): SPLIT cuts the subject at every separator and answers the list, JOIN
	 * takes a list as its subject and answers the string. A list is a value only the evaluator has (diag_text_eval_ops.c) - the form never rewrites either, a list is no literal -
	 * but the cutting and the joining are kuncoat's, run by the same hook as every other op. */
	KGENOME_TEXTUAL_DEC_SPLIT,
	KGENOME_TEXTUAL_DEC_JOIN,
	/* The ops of the command languages (kuncoat's CUTHEAD, CUTTAIL, LENGTH, FORMAT and MAP): the shell's ${x#p} and ${x%p}, ${#x}, printf; tcl's format and string map. */
	KGENOME_TEXTUAL_DEC_CUTHEAD,
	KGENOME_TEXTUAL_DEC_CUTTAIL,
	KGENOME_TEXTUAL_DEC_LENGTH,
	KGENOME_TEXTUAL_DEC_FORMAT,
	KGENOME_TEXTUAL_DEC_MAP,
	KGENOME_TEXTUAL_DEC_COUNT
};

/* The most calls one literal is put through that are looked for: gzinflate(str_rot13(base64_decode(...))). */
#define KGENOME_TEXTUAL_CHAIN_MAX 8u

/*
 * Run `chain` over the literal's value, INNERMOST FIRST (chain[0] is applied to `in`), and answer
 * 1 with the result in `*out` / `*out_len`, valid until the next call. 0 refuses: the value is not
 * what the first decoder reads, or a bound of the caller's fired. A refused literal is kept as
 * typed.
 */
typedef int (*kgenome_textual_decode_fn)(void *user, const uint8_t *chain, uint32_t n_chain,
					 const uint8_t *in, uint32_t len, const uint8_t **out,
					 uint32_t *out_len);

/*
 * ONE FUNCTION OF BYTES, WITH ITS ARGUMENTS: what `op` is asked to do to a value, the way the program wrote the call.
 * s1/s2 are the byte parameters (REPLACE: the search and the replacement; TRANSLATE: the two lists), k1/k2 the numbers
 * (SLICE: the start and the length, with `to_end` when the call gives no length). An op that takes none leaves them 0.
 */
struct kgenome_textual_call {
	uint32_t       op;              /* enum kgenome_textual_decoder */
	const uint8_t *s1, *s2;
	uint32_t       n1, n2;
	int32_t        k1, k2;
	uint32_t       to_end;
	/* KGENOME_TEXTUAL_CALL_*: how the op reads its parameters. TRIM with SET takes its bytes from s1/n1 (the language's own white space) and not php's. */
	uint32_t       flags;
};
#define KGENOME_TEXTUAL_CALL_FIRST 0x1u   /* REPLACE: the first match only */
#define KGENOME_TEXTUAL_CALL_ICASE 0x2u   /* REPLACE: ASCII letters of the search match in either case */
#define KGENOME_TEXTUAL_CALL_SET   0x4u   /* TRIM: s1/n1 are the bytes taken off */
#define KGENOME_TEXTUAL_CALL_DROPTRAIL 0x8u /* SPLIT: the empty pieces at the end are dropped */
#define KGENOME_TEXTUAL_CALL_RANGES 0x10u   /* TRANSLATE: the sets are tr's (a-z) */
#define KGENOME_TEXTUAL_CALL_WSLIST 0x20u   /* JOIN: the subject is a tcl list written as text */
#define KGENOME_TEXTUAL_CALL_REUSE  0x40u   /* FORMAT: run again over the arguments left over (the shell's printf) */
#define KGENOME_TEXTUAL_CALL_ESC    0x80u   /* FORMAT: \n \t \\ in the format are what they say */

/*
 * Run `c` over in[0..len) into out[0..cap), and answer 1 with the length in `*n_out`. 0 refuses: the bytes are not what the
 * function reads, the answer does not fit, or a bound of the caller's fired. The algorithms are the engine's (kuncoat's):
 * the form that rewrites a call on literals and the evaluator that follows a variable ask the same hook and get the same bytes.
 */
typedef int (*kgenome_textual_apply_fn)(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len,
					uint8_t *out, uint32_t cap, uint32_t *n_out);

/*
 * WHICH FUNCTION A CALL NAMES, from the language's table: the op, how many arguments it takes, which of them is the value it
 * works on, and which are its parameters. `numeric` has bit i set when parameter i is a number (substr's start), clear for
 * bytes. The arguments the table has no place for (str_replace's array form, trim's character list) are not in min/max, so a
 * call that uses them is not this function as far as anyone here knows.
 */
#define KGENOME_TEXTUAL_FN_NONE 0xffu
/*
 * WHETHER THE FORM REWRITES A CALL OF THIS FUNCTION whose arguments are all literals (`form`). It is a statement about the
 * language's code, not about the function: a call a program makes on literals for some other reason (a table of bytes: chr(0), chr(10),
 * chr(200)) is data, and a view that rewrote it would move its text for nothing, while str_replace('k','','ckrekatek') and chr(115) are how a
 * name is kept from a scan. NEVER leaves the call to whoever reads the program (the decoders: the decode hook already puts
 * the call's name in front of the text it decoded); ALWAYS rewrites it to the literal it evaluates to; PRINTABLE only when
 * every byte of that literal is printable ascii (chr: a table of chr(0), chr(10), chr(200) is data, and a name is letters).
 *
 * MEASURED, over 13,392 mixed php files and the 1,073 of WordPress 6.8, by the form itself (the calls it wrote as a literal, per function): chr 2,015 calls in
 * 27 files and 2 calls in 2 of WordPress, rtrim 1 call in 1 file, and nothing else - str_replace, strtr, substr, trim, ltrim, strtolower, strtoupper, ucfirst
 * and lcfirst are the idiom of code that hides nothing only when their argument is a variable. A pattern over the text finds 7,991 + 13 chr calls on a number,
 * 75% of them a byte that is not printable (the font and encoding tables of a few files), and those are the ones PRINTABLE keeps as typed. The 76 shells of the
 * corpus hold, folded: str_replace 3, strtolower 2, strtoupper 1. So the view of an ordinary file moves for 30 of 14,465 (0.2%), 29 of them by chr.
 */
enum kgenome_textual_fn_form {
	KGENOME_TEXTUAL_FN_FORM_NEVER = 0,
	KGENOME_TEXTUAL_FN_FORM_ALWAYS,
	KGENOME_TEXTUAL_FN_FORM_PRINTABLE,
	/* The evaluator follows it and the form does not rewrite it, and it is NOT a decoder (a decoder's call is kept by the decode hook; this one is a function of
	 * constants like str_replace). Every method, operator and cast, and a function whose name is too short for the form's call stage (perl's lc). */
	KGENOME_TEXTUAL_FN_FORM_EVAL
};

/*
 * HOW A ROW IS WRITTEN IN A PROGRAM (kgenome_textual_fn.shape), and so what its name is spelt as:
 *   CALL    name(args): php's str_replace, vbscript's Left, lua's string.rep. The arguments are the row's, receiver-less.
 *   METHOD  receiver.name(args): the row's name begins with the "." (".replace"), and the receiver is ARGUMENT 0: `"abc".replace("a", "b")` is the call
 *           replace("abc", "a", "b"), so a row's counts (min_args, max_args, subject, param) all include it.
 *   OP      receiver OP right: the name is the operator as written ("-replace", "x", "*"). Argument 0 is the left side and the right side's values follow it
 *           (a comma list where the row says RIGHT_LIST: powershell's `-replace 'a','b'`). `prec` says where it binds - 0: looser than the language's join (powershell's
 *           -replace: `'a' + 'b' -replace 'a','c'` is `('a' + 'b') -replace ...`), 1: tighter than it (python's `*`: `'a' + 'b' * 2` is `'a' + ('b' * 2)`).
 *   SUFFIX  receiver followed by a spelling and nothing else: python's `[::-1]`.
 *   CAST    a spelling in front of its operand: powershell's `[char]65`.
 * All of them are read by the constant evaluator (phenotype/diag_text_eval_ops.c) and by nothing else; the form's call stage reads CALL rows only.
 */
enum kgenome_textual_shape {
	KGENOME_TEXTUAL_SHAPE_CALL = 0,
	KGENOME_TEXTUAL_SHAPE_METHOD,
	KGENOME_TEXTUAL_SHAPE_OP,
	KGENOME_TEXTUAL_SHAPE_SUFFIX,
	KGENOME_TEXTUAL_SHAPE_CAST,
	/* The command languages (sh, batch, tcl) have no expressions: a value is a WORD, and these two are how a word is changed. CMD: a command whose output is the value (`$(rev)`, tcl's
	 * `[string map ...]`); the name is the words that name it ("string map"), the arguments are the words after (a row with STDIN has the pipe's value as argument 0). EXPAND: an
	 * operator written after a variable's name in its expansion (`${x//a/b}` is "//", batch's `%x:a=b%` is ":"); its operands are the row's `sep`-separated parts. */
	KGENOME_TEXTUAL_SHAPE_CMD,
	KGENOME_TEXTUAL_SHAPE_EXPAND
};

/*
 * WHAT chr(n) IS, in the language's own function (kgenome_textual_fn.chr). The byte or the character a number names is the language's: php takes the
 * number modulo 256 (and a negative one too); perl and lua take 0..255 and call the rest an error (perl's wide characters are not bytes); vbscript's Chr
 * is ANSI and is taken for 0..127 only (above it the byte depends on the code page); python's chr is a code point, 0..0x10FFFF, and javascript's
 * String.fromCharCode a UTF-16 unit - the number modulo 65536 - and vbscript's ChrW one of 0..65535: a character above 0x7f is written as its utf-8
 * bytes, because that is what the value of a literal holding it is (a surrogate has no utf-8 form here: refused). A number the flavour refuses
 * refuses the call.
 */
enum kgenome_textual_chr {
	KGENOME_TEXTUAL_CHR_PHP = 0,    /* n & 0xff */
	KGENOME_TEXTUAL_CHR_BYTE,       /* 0..255 */
	KGENOME_TEXTUAL_CHR_ASCII,      /* 0..127 */
	KGENOME_TEXTUAL_CHR_UTF8,       /* 0..0x10FFFF, utf-8, no surrogate */
	KGENOME_TEXTUAL_CHR_UTF16,      /* n mod 65536, utf-8, no surrogate */
	KGENOME_TEXTUAL_CHR_UCS2        /* 0..65535, utf-8, no surrogate */
};

/* What a function demands of its arguments beyond the table's shape (kgenome_textual_fn.flags). Each is a fact about the LANGUAGE's function, and a call that
 * breaks one is not evaluated: it stays as the program wrote it. */
#define KGENOME_TEXTUAL_FN_ASCII   0x1u     /* the subject is ASCII: a byte above 0x7f has a case in a locale (vbscript's LCase) or is more than one unit of a string (javascript's slice), so a subject with one is refused */
#define KGENOME_TEXTUAL_FN_BASE1   0x2u     /* the first numeric parameter counts from 1 (vbscript's Mid: 0 and below are errors) */
#define KGENOME_TEXTUAL_FN_NONNEG  0x4u     /* a numeric parameter below 0 is an error in the language, not a count from the end (php's substr); of a REPEAT, a count below 0 is refused and not empty */
#define KGENOME_TEXTUAL_FN_ENDIDX  0x8u     /* the second numeric parameter is where the cut ENDS (javascript's slice(a, b): exclusive), not how long it is. With BASE1 it is lua's string.sub(s, i, j): j counts from 1 and is
                                             * INCLUDED, which is the same number as an exclusive end counted from 0 - no flag of its own */
#define KGENOME_TEXTUAL_FN_SWAP    0x20u    /* with ENDIDX: a start past the end swaps them (javascript's substring) */
#define KGENOME_TEXTUAL_FN_FROMEND 0x40u    /* the one count is how many bytes of the END to keep (vbscript's Right) */
#define KGENOME_TEXTUAL_FN_NOEMPTY 0x80u    /* the first byte parameter is not empty: an empty search inserts between every character in these languages, which the op does not */
#define KGENOME_TEXTUAL_FN_FIRST   0x100u   /* REPLACE: the first match only */
#define KGENOME_TEXTUAL_FN_ICASE   0x200u   /* REPLACE: the search matches in either case (powershell's -replace); the subject is ASCII then, where case folding is the language's own */
#define KGENOME_TEXTUAL_FN_UNIQUE  0x400u   /* TRANSLATE: no byte of the first list twice (ruby's tr: which pair wins is the language's) */
#define KGENOME_TEXTUAL_FN_ONECHAR 0x800u   /* the subject is exactly one byte (vbscript's String(n, "c")) */
#define KGENOME_TEXTUAL_FN_STRICT  0x1000u  /* a start or length past the end is an exception, not a clamp (.NET's Substring): refused */
#define KGENOME_TEXTUAL_FN_NUMTYPED 0x2000u /* a numeric parameter must be a number of the program, not a string that spells one ([char]"65" is an error, [char]65 is "A"): the evaluator asks */
#define KGENOME_TEXTUAL_FN_MULTI   0x4000u  /* the call answers more than one value (lua's gsub: the text and a count): evaluated only where one value is taken */
#define KGENOME_TEXTUAL_FN_ONESEP  0x10000u /* the first byte parameter is one byte (powershell's .Split(','): a longer string is a set of characters in Windows PowerShell and a string in PowerShell 7) */
#define KGENOME_TEXTUAL_FN_NOPAREN 0x20000u /* a METHOD that takes no argument may be written without brackets (ruby's "abc".reverse); javascript's .trim without them is the function itself, so no other language says it */
#define KGENOME_TEXTUAL_FN_NOGROUP 0x40000u /* OP: the left side is not a bracket - perl's `("ab") x 3` is a LIST repetition in list context, and `"ab" x 3` the string */
#define KGENOME_TEXTUAL_FN_LIST_RECV 0x8000u /* JOIN: the receiver is the list and the separator is argument 1 (javascript, ruby, powershell -join); without it argument 0 is the separator and the list follows (python, perl, [string]::Join) */

struct kgenome_textual_fn {
	uint32_t op;
	uint8_t  min_args, max_args;
	uint8_t  subject;
	uint8_t  param[2];
	uint8_t  numeric;
	uint8_t  form;          /* enum kgenome_textual_fn_form */
	uint8_t  chr;           /* chr: enum kgenome_textual_chr. With max_args above 1 every argument is one more character (String.fromCharCode(104, 105)) */
	uint32_t flags;         /* KGENOME_TEXTUAL_FN_* */
	uint8_t  shape;         /* enum kgenome_textual_shape */
	uint8_t  prec;          /* OP: 1 binds tighter than the language's join, 0 looser */
	uint8_t  list;          /* KGENOME_TEXTUAL_LIST_*: what the right side of an OP and the result of a SPLIT are */
	/* Bytes a parameter must not hold, by the role it has (bad[0] the subject, bad[1] the first byte parameter, bad[2] the second): a call that has one is not this
	 * function as far as anyone here knows. Powershell's -replace takes a regular expression, so a pattern with a metacharacter is refused and one without is the plain
	 * text it matches; javascript's replace reads "$" in its replacement. NULL: any byte. */
	const char *bad[3];
	/* TRIM: the bytes taken off the ends where they are not php's (python's strip, javascript's trim, vbscript's Trim: a space and nothing else). NULL: php's. A JOIN with
	 * COLLECT_ALL: the separator the words are joined with (echo's blank, string cat's none). */
	const char *set;
	/* EXPAND: the byte that separates the operands in the expansion's text ("/" in ${x//a/b}, "=" in %x:a=b%); 0: one operand, or none. */
	uint8_t     sep;
	/* The KGENOME_TEXTUAL_CALL_* flags the op is run with: how this language's function reads what the op takes (tr's ranges, the shell's run-again printf). */
	uint32_t    opflags;
};
#define KGENOME_TEXTUAL_FN_STDIN       0x80000u     /* CMD: argument 0 is what the pipe carries (rev, tr); a stage with none refuses */
#define KGENOME_TEXTUAL_FN_SETARG      0x100000u    /* TRIM: the set to take off is the first parameter, when the call gives one (tcl's string trim s chars) */
#define KGENOME_TEXTUAL_FN_ENDWORD     0x200000u    /* a numeric parameter may be `end`, `end-N`, `end+N` (tcl's string range): counted from the last character */
#define KGENOME_TEXTUAL_FN_INCL        0x400000u    /* with ENDIDX: the end counted from 0 and INCLUDED (tcl's string range s first last) */
#define KGENOME_TEXTUAL_FN_ECHOOPT     0x800000u    /* CMD: leading words made of the letter n after a "-" are options that change nothing (echo -n); one with e or E is refused */
#define KGENOME_TEXTUAL_FN_COLLECT_ALL 0x1000000u   /* CMD: every word is one element of the list that is argument 0 of the op (echo, string cat, concat) */
#define KGENOME_TEXTUAL_FN_COLLECT_REST 0x2000000u  /* CMD: argument 0 is the first word and the rest are the list that is argument 1 (printf, format) */
#define KGENOME_TEXTUAL_FN_NODASH      0x4000000u   /* a byte argument does not begin with "-" (a program would read it as an option) */
#define KGENOME_TEXTUAL_FN_NOEDGE      0x8000000u   /* every collected word has no white space at either end and is not empty (tcl's concat trims and drops) */
#define KGENOME_TEXTUAL_FN_PREFIXOP    0x10000000u  /* EXPAND: the operator stands BEFORE the name (${#x}) */
#define KGENOME_TEXTUAL_FN_PLAINNUM    0x20000000u  /* a numeric parameter is digits and nothing else: no sign (the shell's ${x:-0} is a default, not an offset of -0) */
#define KGENOME_TEXTUAL_FN_BASHSLICE 0x40000000u /* SLICE: bash's ${x:o:l}: a blank before the offset lets it be negative (`${x: -3}`; without the blank `:-` is the default), and an offset before the start gives the empty text (php's substr clamps) */
/* A row's `list`. RIGHT: the right side of an operator is a comma list of values (powershell -replace 'a','b'). DROP_TRAILING: SPLIT removes the empty strings at the end of
 * the list (ruby), and a JOIN with no separator joins with nothing (ruby; javascript's default is "," so its row says two arguments). VARIADIC: JOIN reads every argument after
 * the separator as one element (perl's join, [string]::Join). */
#define KGENOME_TEXTUAL_LIST_RIGHT 0x1u
#define KGENOME_TEXTUAL_LIST_DROP_TRAILING 0x2u
#define KGENOME_TEXTUAL_LIST_VARIADIC 0x4u   /* JOIN: every argument after the separator is one element (perl's join, [string]::Join) */
/* 1 and `*out` filled when `name` (len bytes, any case where the language has none) is a function the language's table has. */
int kgenome_textual_fn_find(uint32_t lang, const uint8_t *name, uint32_t len, struct kgenome_textual_fn *out);
/* The shapes the language's table has rows of, a bit each (1u << enum kgenome_textual_shape): 0 for a language with no table. A reader that looks for a method, an operator or a cast only
 * where the language has any pays nothing for the rest. */
uint32_t kgenome_textual_fn_shapes(uint32_t lang);
/* Row `k` of the language's table, name as spelt (lower case where the language folds) and the function; 0 past the last. For a reader that has to match a spelling no name lookup finds: an
 * operator is written between its operands, a cast in front of its operand. */
int kgenome_textual_fn_row(uint32_t lang, uint32_t k, const char **name, struct kgenome_textual_fn *out);

/*
 * THE WORDS OF A COMMAND LANGUAGE (sh, batch, tcl). They have no expressions: a value is a WORD - what a command is given - and a word is pieces written one against the
 * other: a literal in any of the language's quotings, a variable, an expansion of a variable (`${x//a/b}`, batch's `%x:a=b%`), the output of a command (`$(..)`, tcl's `[..]`).
 * What a word comes to is the evaluator's (diag_text_cmdval.c: it has the variables); what each piece IS - where a quote ends, what a backslash does inside one, where the name of
 * a variable stops, which operator an expansion spells - is the language's, and is here, a hook of its row (`cmd`): the same two calls whatever the language.
 *
 * kgenome_textual_word_read reads ONE word at `from` and tells the sink its pieces in order; the literal bytes are given as the language reads them (escapes applied). It answers
 * where the word ends, or 0 for one it cannot say exactly - a pattern that globs, a brace expansion, `$((..))`, `$1`, an unterminated quote, a `$(`/`${` group nested past
 * KGENOME_TEXTUAL_SH_DEPTH (32; the stack a text takes is not the text's to choose), a construct no row of the table spells - and then what the sink was told is not the word. `ctx`: WORD stops at the blank or the byte that ends a command and refuses what the shell would expand into
 * more words or a path; OPERAND is the text of an operand of an expansion, where a blank is a byte, and stops at `limit`; TEXT is batch's whole right side, to `limit`.
 * The sink answers 0 to stop. `quoted` says a variable or a command is read inside double quotes, where the shell does not split its answer into words or glob it.
 */
struct kgenome_textual_range {
	uint32_t off, len;
};
/* Is the range of `in` exactly the word `s`. The one spelling of this question for the command readers (sh, tcl) and the evaluator over them. */
static inline int kgenome_textual_range_is(const uint8_t *in, struct kgenome_textual_range w, const char *s)
{
	return w.len == strlen(s) && !memcmp(in + w.off, s, w.len);
}
struct kgenome_textual_word_sink {
	void *user;
	int (*lit)(void *user, const uint8_t *p, uint32_t n);
	int (*var)(void *user, struct kgenome_textual_range name, int quoted);
	/* `row` is the index of the expansion's row in the language's table (kgenome_textual_fn_row); `arg` its operands as written */
	int (*expand)(void *user, struct kgenome_textual_range name, uint32_t row, const struct kgenome_textual_range *arg, uint32_t n_arg, int quoted);
	int (*cmd)(void *user, struct kgenome_textual_range inner, int quoted);
};
#define KGENOME_TEXTUAL_CTX_WORD    0u
#define KGENOME_TEXTUAL_CTX_OPERAND 1u
#define KGENOME_TEXTUAL_CTX_TEXT    2u
/* ASSIGN is the VALUE of a variable assignment, read as a WORD (sh): the shell expands a tilde-prefix there after the first "=" (the start of the value) and after every unquoted ":" -
 * `v=a:~` is "a:" and $HOME - which a plain word does not, so the value of such a word is the machine's and no constant (tests/unit/diag_text_oracle.c). */
#define KGENOME_TEXTUAL_CTX_ASSIGN  3u
uint32_t kgenome_textual_word_read(uint32_t lang, const uint8_t *in, uint32_t from, uint32_t limit, uint32_t ctx, const struct kgenome_textual_word_sink *sk);

/*
 * ONE COMMAND: the words of a simple command read at `from` (blank, comment and, in the shell, here-document bodies skipped), as ranges, and what ended it. `term` is the byte -
 * a line break, ";", "&", "|", "(", ")" - or 0 at `limit`; `pipe` says a single "|" (what goes on is the next command's input) and `andor` a doubled "&&" or "||". A redirection
 * is not a word (`redirect`). `paren` is the net count of unquoted "(" over ")" in the command's own text. In batch `rest` is the raw text after the first word to the end of the command (set
 * takes it whole), with the blanks that lead it skipped and the ones that trail it kept. `end` is where the next command is looked for. A here-document the command opens is
 * remembered in `hd_*` so the one that comes after the line break skips its body: pass the previous command's to the next call (zero them at the start).
 * 1 for a command (n may be 0: an empty line), 0 at the end of the text. A call with from < limit ALWAYS moves: `end` is above `from`, and an unclosed word (see `open`) ends at `limit`.
 */
#define KGENOME_TEXTUAL_CMD_WORDS 32u
/* How deep the shell's readers follow `"$( "$( ... )" )"` (one spelling for the lexer, sh_lex.c, and the word reader, sh_cmd.c): the deepest wrapped payload this tree has met is far under it. */
#define KGENOME_TEXTUAL_SH_DEPTH 32u
struct kgenome_textual_cmd {
	uint32_t n;
	struct kgenome_textual_range w[KGENOME_TEXTUAL_CMD_WORDS];
	uint32_t end;
	uint8_t  term, pipe, andor, redirect, many;
	/* `open`: a quote, a brace, a bracket or a group of the command's last word did not close, so the word is the rest of the text as the shell and tcl read it, and `end`
	 * is `limit` (an unclosed word is read to the end ONCE; the reader always moves). `deep`: of those, the shell's `$(` and `${` groups nested past
	 * KGENOME_TEXTUAL_SH_DEPTH, which are read as not closed so that the stack a text takes is not the text's to choose. */
	uint8_t  open, deep;
	int32_t  paren;
	struct kgenome_textual_range rest;
	struct kgenome_textual_range hd_delim;
	uint8_t  hd_dash;
};
int kgenome_textual_cmd_read(uint32_t lang, const uint8_t *in, uint32_t from, uint32_t limit, struct kgenome_textual_cmd *c);

/*
 * THE ASSIGNMENTS A COMMAND MAKES: the shell's `x=value` (also after export, readonly, declare), batch's `set v=value` and `set "v=value"`, tcl's `set v value` and `append v ..`. `name` is where
 * the variable's name is written and `value` the text it is given (a word; in batch and for a quoted set raw text, see RAW; for tcl's append the words from the first to the last, see
 * WORDS). ENV: `x=1 cmd` gives x to cmd alone (it is a write the evaluator must know of and not a value). LOCAL: `local x=` (a function's own). UNREAD: the command writes the name and
 * the value is not text this reads (batch's `set /a`, `set /p`, a `+=`). Answers how many were written to `a`.
 */
#define KGENOME_TEXTUAL_ASSIGN_RAW    0x1u
#define KGENOME_TEXTUAL_ASSIGN_WORDS  0x2u
#define KGENOME_TEXTUAL_ASSIGN_ENV    0x4u
#define KGENOME_TEXTUAL_ASSIGN_LOCAL  0x8u
#define KGENOME_TEXTUAL_ASSIGN_UNREAD 0x10u
#define KGENOME_TEXTUAL_ASSIGN_CALL   0x20u   /* batch's `call set`: expanded twice */
struct kgenome_textual_assign {
	struct kgenome_textual_range name, value;
	uint8_t flags;
};
uint32_t kgenome_textual_cmd_assigns(uint32_t lang, const uint8_t *in, const struct kgenome_textual_cmd *c, struct kgenome_textual_assign *a, uint32_t max);
/* Does the language have command-word rows (a reader of words)? */
int kgenome_textual_has_words(uint32_t lang);

/* One argument of a call: its VALUE as bytes (a number is its decimal text, which is how a program writes it). */
struct kgenome_textual_arg {
	const uint8_t *p;
	uint32_t       n;
};

/* The argument as a number, the way php reads a decimal literal: an optional sign and digits, none of them after the value passed a hundred
 * million. 1 and `*n`, or 0 when it is anything else. What every reader of a call's numeric argument (the form, the evaluator of the TEXT
 * route, an array index) asks, so they agree on what a number is. */
int kgenome_textual_arg_num(const struct kgenome_textual_arg *a, long *n);



/*
 * THE ONE PLACE A CALL ON CONSTANTS IS RUN: which argument is the subject and which are the parameters, which parameters
 * are numbers (read as decimal, an optional sign, at most a hundred million before the last digit), the optional one a call
 * leaves out, chr's byte - then the hook for everything else. The form (a call written as the literal it evaluates to) and the
 * constant evaluator of the TEXT route both call it, and so cannot disagree about what `substr('abc', -1)` is.
 * 1 with the answer in out[0..*n_out); 0 refuses: the argument count is not the function's, a number is not one, the hook is NULL
 * or refused, or the answer does not fit `cap`.
 */
int kgenome_textual_fn_run(const struct kgenome_textual_fn *f, const struct kgenome_textual_arg *a, uint32_t n_args,
			   kgenome_textual_apply_fn apply, void *apply_user, uint8_t *out, uint32_t cap, uint32_t *n_out);

/*
 * A VALUE WRITTEN WHERE IT WAS COMPUTED. A script that builds a name or a payload out of pieces (`$u = str_replace('T|', '', $a . $b)`) says
 * what it makes only when it runs; once something has worked out the value, the text can say it instead: the bytes [off, off+len) of the input
 * become ONE LITERAL whose value is `value`, written as the language writes a literal (its `quote` row, textual_lang.h: the delimiter and what each byte
 * is written as, so that reading the literal gives back exactly the value). The ranges are in order and none holds another. Nothing is
 * decoded or computed here: who worked the value out is the caller's - the same evaluator the diagnose route reads names with - and this only puts
 * it in the text. Answers the length written to `out`, or 0 for a language with no quote row, ranges out of order or past the input, or `cap` too
 * small (kgenome_textual_subst_cap is exactly enough) or a value the language cannot write (kgenome_textual_subst_can).
 */
struct kgenome_textual_subst {
	uint32_t       off, len;
	const uint8_t *value;
	uint32_t       n;
	/* BARE: the value is a NAME and is written as it is, not as a literal - what a call's head says once it is known (`$l('', $c)` with `$l` the one string
	 * 'create_function` is `create_function('', $c)`). Refused (the call answers 0) when the value is not a name (kgenome_textual_name_ok). */
	uint8_t        bare;
};
/* Is `v` (n bytes) a plain name a call can be made with: letters, digits, "_", bytes above 0x7f and "\\" (a namespace), not beginning with a digit, not empty. */
int kgenome_textual_name_ok(const uint8_t *v, uint32_t n);
/* The size the output needs: the input and, for each range, what its value is written as (a value the language refuses counts what its widest spelling would). */
/* Put ranges that came from more than one source in the order kgenome_textual_subst needs: by offset, a range that begins inside the one before it dropped (the
 * one that holds it says the rest: a call head inside a computed right side). Sorts in place and answers how many are left. */
uint32_t kgenome_textual_subst_order(struct kgenome_textual_subst *s, uint32_t ns);
uint64_t kgenome_textual_subst_cap(uint32_t lang, const uint8_t *in, uint32_t n, const struct kgenome_textual_subst *s, uint32_t ns);
/* Would kgenome_textual_subst write this value (`n` bytes, `v`) in a language's text: the language has a `quote` row and the value is one its literal can
 * hold (a line break in a vbscript string, a "%>" in a page's island and the like are not). A caller offers a range only when it says yes. */
int kgenome_textual_subst_can(uint32_t lang, const uint8_t *v, uint32_t n);
uint32_t kgenome_textual_subst(uint32_t lang, const uint8_t *in, uint32_t n, const struct kgenome_textual_subst *s, uint32_t ns,
			       uint8_t *out, uint32_t cap);

struct kgenome_textual_form_req {
	const uint8_t *in;
	uint32_t       n;
	uint32_t       lang;    /* enum kgenome_textual_lang_id */
	uint32_t       flags;   /* KGENOME_TEXTUAL_FRAGMENT, KGENOME_TEXTUAL_KEEP_JOINS */
	uint8_t       *out;     /* the caller's buffer */
	/* Its size: at least KGENOME_TEXTUAL_FORM_CAP(n); with `decode` the bytes beyond that are
	 * what decoded literals may take. A decoded literal that would not leave room for the rest
	 * of the text stays as typed and is counted in n_refused: nothing is cut to fit. */
	uint64_t       cap;
	kgenome_textual_decode_fn decode;       /* NULL: nothing is decoded */
	void          *decode_user;
	/* The hook that runs a function of bytes. With it, a call of a function the language's table says the form rewrites
	 * (kgenome_textual_fn_form) whose arguments are all literals - strings and integers, or calls of the same kind, which
	 * are rewritten first - is written as the one literal it evaluates to, and joins with the literals around it like any
	 * other. NULL: no call is rewritten. KGENOME_TEXTUAL_KEEP_JOINS turns it off as well. A call is refused (it stays as typed
	 * and is counted in n_refused) when its answer would not leave room for the rest of the text, so `cap` should hold what a
	 * long answer takes beyond KGENOME_TEXTUAL_FORM_CAP(n), as it does for the decoders. */
	kgenome_textual_apply_fn apply;
	void          *apply_user;
};

struct kgenome_textual_form_res {
	uint32_t n_out;         /* bytes written; 0 when the status is not OK or OPEN */
	uint32_t n_open;        /* spans kept as typed because they were not closed */
	uint32_t n_decoded;     /* literals the hook decoded, and whose value is in the output */
	uint32_t n_folded;      /* joins of literals written as one literal */
	uint32_t n_refused;     /* literals under a decoder, and calls on literals, that stayed as typed */
	uint32_t n_bound;       /* the lexer's work bounds that fired (kgenome_textual_lex_res.n_bound) */
	uint32_t n_calls;       /* calls written as the literal they evaluate to */
	uint32_t n_fn[KGENOME_TEXTUAL_DEC_COUNT];       /* of them, by the op of the function (a nested call counts once for each) */
};

/* OK and OPEN both mean `out` holds the form; the others mean it holds nothing. */
enum kgenome_textual_status kgenome_textual_form(const struct kgenome_textual_form_req *rq,
						 struct kgenome_textual_form_res *res);

/*
 * VALUE. What a string literal HOLDS, as the language reads it: the bytes between its delimiters with every
 * escape turned into what it stands for - "\x59\n" in php, '\/' in js, b"\x59" in python, "" in a vbscript
 * string. A decoder is put over the value and not over the text: base64_decode("YWJj\n") decodes "YWJj" and a
 * newline, and the same text read as bytes ends in a backslash and an n.
 *
 * `lit` is the whole literal as a span gave it - delimiters, prefix and all - with the span's own open_len,
 * close_len and flags. A literal that has no value without running the program is not given one: a php
 * string with a $name or {$ in it, a template with a ${ }, a python f-string field, a java text block (its
 * indentation rule is not applied here), a python \N{name}. The value is never longer than the text between
 * the delimiters, so `cap` of that length always suffices.
 */
struct kgenome_textual_value_req {
	uint32_t       lang;    /* enum kgenome_textual_lang_id */
	const uint8_t *lit;
	uint32_t       len, open_len, close_len;
	uint8_t        flags;   /* the span's KGENOME_TEXTUAL_F_* */
	uint8_t       *out;
	uint64_t       cap;
};

struct kgenome_textual_value_res {
	uint32_t n_out;         /* bytes written; 0 when the status is not OK */
};

/* OK, or KGENOME_TEXTUAL_NO_LANG, NO_VALUE (it has none), SMALL (cap is below the text between the delimiters). */
enum kgenome_textual_status kgenome_textual_value(const struct kgenome_textual_value_req *rq,
						  struct kgenome_textual_value_res *res);

/* "code", "string", ...: for a tool that prints spans. Never NULL. */
const char *kgenome_textual_kind_name(uint32_t kind);

#endif /* KGENOME_TEXTUAL_H */
