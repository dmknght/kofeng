/*
 * php_fn.c - the functions php builds a value with, as the table kgenome_textual_fn_find reads: the decoders a script
 * puts a payload through and the string functions it builds a name with (str_replace, strtr, substr, the case maps).
 *
 * ONE ROW PER FUNCTION, in the order of its php signature: the argument that is the value is `subject`, the others are
 * parameters. Arguments the table has no place for - str_replace's array form and its fourth argument, trim's character
 * list, base64_decode's strict flag, gzinflate's length - are not in max, so a call that uses them is not read as this
 * function. [Unverified] against php itself: no php is installed here; the signatures are the documented ones.
 */

#include "php.h"

static const struct kgenome_textual_fn_row fns[] = {
	KGENOME_TEXTUAL_FN_DEC("base64_decode", B64),
	KGENOME_TEXTUAL_FN_DEC("hex2bin", HEXSTRICT),
	KGENOME_TEXTUAL_FN_DEC("urldecode", URL),
	KGENOME_TEXTUAL_FN_DEC("rawurldecode", RAWURL),
	KGENOME_TEXTUAL_FN_DEC("str_rot13", ROT13),
	KGENOME_TEXTUAL_FN_DEC("strrev", REVERSE),
	KGENOME_TEXTUAL_FN_DEC("gzinflate", INFLATE),
	KGENOME_TEXTUAL_FN_DEC("gzuncompress", ZLIB),
	KGENOME_TEXTUAL_FN_DEC("gzdecode", GZIP),
	KGENOME_TEXTUAL_FN_STR1("strtolower", LOWER, 0),
	KGENOME_TEXTUAL_FN_STR1("strtoupper", UPPER, 0),
	KGENOME_TEXTUAL_FN_STR1("ucfirst", UCFIRST, 0),
	KGENOME_TEXTUAL_FN_STR1("lcfirst", LCFIRST, 0),
	KGENOME_TEXTUAL_FN_STR1("trim", TRIM, 0),
	KGENOME_TEXTUAL_FN_STR1("ltrim", LTRIM, 0),
	KGENOME_TEXTUAL_FN_STR1("rtrim", RTRIM, 0),
	/* str_replace(search, replace, subject) */
	KGENOME_TEXTUAL_FN("str_replace", REPLACE, 3, 3, 2, 0, 1, 0, 0),
	/* strtr(subject, from, to) */
	KGENOME_TEXTUAL_FN("strtr", TRANSLATE, 3, 3, 0, 1, 2, 0, 0),
	/* chr(code): the one function whose argument is a number and which has no subject; a number is taken mod 256 */
	KGENOME_TEXTUAL_FN_CHR("chr", 1, KGENOME_TEXTUAL_CHR_PHP),
	/* substr(subject, start, length = to the end) */
	KGENOME_TEXTUAL_FN("substr", SLICE, 2, 3, 0, 1, 2, 3, 0),
	/* explode(separator, string): a LIST, which only a join (implode, join) takes - the evaluator's. An empty separator is a ValueError in php 8 (the op refuses it), and a
	 * third argument (a limit) is not in max. implode(separator, array) and implode(array): the separator is "" when there is none; the list is written `array(...)` or `[...]`. */
	KGENOME_TEXTUAL_ROW("explode", SPLIT, 2, 2, 1, 0, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_EVAL),
	KGENOME_TEXTUAL_ROW("implode", JOIN, 1, 2, 0, 1, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_EVAL),
	KGENOME_TEXTUAL_ROW("join", JOIN, 1, 2, 0, 1, KGENOME_TEXTUAL_FN_NO, 0, 0, KGENOME_TEXTUAL_K_EVAL),
};

const struct kgenome_textual_fn_table kgenome_textual_php_fn_table = { fns, (uint32_t)(sizeof fns / sizeof fns[0]) };
