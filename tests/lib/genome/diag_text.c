/*
 * diag_text - the TEXT route: a script's calls are nodes in the one vocabulary, and a value flowing into an argument is a link.
 *
 * What is checked is the graph and nothing about a verdict: which capability each call has, which node feeds which, in which
 * role - and that what the route is told not to follow it does not invent (a name in a comment or a literal, a variable
 * that never reached the call).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

#include "diag_text_gen.h"
#include "diag_text_graph.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

struct names { char v[16][32]; int n; };

static void collect(void *u, const char *name, uint32_t len)
{
	struct names *m = u;

	if (m->n < 16 && len < 32) {
		memcpy(m->v[m->n], name, len);
		m->v[m->n++][len] = 0;
	}
}

static struct kgenome_diag_scan *scan(const char *src)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = KGENOME_TEXTUAL_LANG_PHP };

	return kgenome_diag_scan_text(&rq);
}

static void case_(const char *src, int n_decode, int n_eval, int dec_eval, int req_eval, int req_exec)
{
	struct kgenome_diag_scan *s = scan(src);

	CK(s != NULL, "scan of %s", src);
	if (!s)
		return;
	CK(count(s, KGENOME_NUCLEO_DECODE) == n_decode, "decode nodes %d, wanted %d in: %s", count(s, KGENOME_NUCLEO_DECODE), n_decode, src);
	CK(count(s, KGENOME_NUCLEO_EVAL) == n_eval, "eval nodes %d, wanted %d in: %s", count(s, KGENOME_NUCLEO_EVAL), n_eval, src);
	CK(linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 0xff) == dec_eval, "decode -> eval, wanted %d in: %s", dec_eval, src);
	CK(linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff) == req_eval, "request -> eval, wanted %d in: %s", req_eval, src);
	CK(linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) == req_exec, "request -> exec, wanted %d in: %s", req_exec, src);
	kgenome_diag_scan_free(s);
}


struct tpl {
	const char *src;
	int dec_eval, req_eval, req_exec, req_dec, req_dyn;
};

static void random_names_and_spacing(void)
{
	static const struct tpl T[] = {
		/* a decode kept in a variable, then run: the variable is the link */
		{ "<?php @$~1@=@base64_decode@(@'abc'@)@;@eval@(@$~1@)@;", 1, 0, 0, 0, 0 },
		{ "<?php @$~1@=@gzinflate@(@base64_decode@(@$~2@)@)@;@$~3@=@$~1@;@eval@(@$~3@)@;", 1, 0, 0, 0, 0 },
		/* a request value through one and two variables, to a command and to an eval */
		{ "<?php @$~1@=@$_POST@[@'x'@]@;@system@(@$~1@)@;", 0, 0, 1, 0, 0 },
		{ "<?php @$~1@=@$_GET@[@\"y\"@]@;@$~2@=@$~1@;@exec@(@$~2@)@;@eval@(@$~2@)@;", 0, 1, 1, 0, 0 },
		/* a function name kept in a literal, joined from pieces, then called through the variable */
		{ "<?php @$~1@=@'sys'@.@'tem'@;@$~1@(@$_REQUEST@[@'c'@]@)@;", 0, 0, 1, 0, 0 },
		/* the spelling of a function does not matter, the spelling of a variable does */
		{ "<?php @EvAl@(@BaSe64_DeCoDe@(@$~1@)@)@;", 1, 0, 0, 0, 0 },
		{ "<?php @$~1@=@Base64_Decode@(@'x'@)@;@EVAL@(@$~1@)@;", 1, 0, 0, 0, 0 },
		/* the request named the callee */
		{ "<?php @$_POST@[@0@]@(@$_POST@[@1@]@)@;", 0, 0, 0, 0, 1 },
		/* THE REQUEST'S OWN BODY is the request, and a call that writes an argument hands it on: the value reaches $~2 through
		 * preg_match / preg_match_all / parse_str, and from there the eval. */
		{ "<?php @$~1@=@file_get_contents@(@'php://input'@)@;@preg_match@(@'/x/'@,@$~1@,@$~2@)@;@eval@(@$~2@[@0@]@)@;", 0, 1, 0, 0, 0 },
		{ "<?php @preg_match_all@(@'/x/'@,@file_get_contents@(@'PHP://Input'@)@,@$~2@)@;@eval@(@$~2@[@1@]@[@0@]@)@;", 0, 1, 0, 0, 0 },
		{ "<?php @parse_str@(@file_get_contents@(@'php://input'@)@,@$~1@)@;@eval@(@$~1@[@'a'@]@)@;", 0, 1, 0, 0, 0 },
		{ "<?php @parse_str@(@$_POST@[@'q'@]@,@$~3@)@;@system@(@$~3@[@'c'@]@)@;", 0, 0, 1, 0, 0 },
		{ "<?php @$~1@=@fopen@(@'php://input'@,@'r'@)@;@eval@(@$~1@)@;", 0, 1, 0, 0, 0 },
		/* NOT the request: another stream, a name the program builds, a pattern (not the subject), a use BEFORE the call, another variable */
		{ "<?php @$~1@=@file_get_contents@(@'php://stdin'@)@;@eval@(@$~1@)@;", 0, 0, 0, 0, 0 },
		{ "<?php @$~1@=@file_get_contents@(@$~2@)@;@eval@(@$~1@)@;", 0, 0, 0, 0, 0 },
		{ "<?php @preg_match@(@$_GET@[@'re'@]@,@'subject'@,@$~2@)@;@eval@(@$~2@[@0@]@)@;", 0, 0, 0, 0, 0 },
		{ "<?php @eval@(@$~2@[@0@]@)@;@preg_match@(@'/x/'@,@$_GET@[@'a'@]@,@$~2@)@;", 0, 0, 0, 0, 0 },
		{ "<?php @preg_match@(@'/x/'@,@$_GET@[@'a'@]@,@$~2@)@;@eval@(@$~3@[@0@]@)@;", 0, 0, 0, 0, 0 },
		/* nested through functions that are not nodes, and through an operator */
		{ "<?php @eval@(@trim@(@strrev@(@gzinflate@(@base64_decode@(@$~1@)@)@)@)@.@';'@)@;", 1, 0, 0, 0, 0 },
	};
	char names[3][20], src[1024];
	const char *vn[3] = { names[0], names[1], names[2] };
	uint32_t i, k, iter;

	for (iter = 0; iter < 3000u; iter++) {
		/* three DIFFERENT variables: a template that says "another variable" must not be given the same one twice */
		do {
			for (k = 0; k < 3u; k++)
				rname(names[k]);
		} while (!strcmp(names[0], names[1]) || !strcmp(names[0], names[2]) || !strcmp(names[1], names[2]));
		for (i = 0; i < sizeof T / sizeof T[0]; i++) {
			struct kgenome_diag_scan *sc;

			expand(src, sizeof src, T[i].src, vn);
			sc = scan(src);
			CK(sc != NULL, "scan of: %s", src);
			if (!sc)
				continue;
			CK(linked(sc, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 0xff) == T[i].dec_eval, "decode->eval %d, names %s %s %s, in: %s",
			   T[i].dec_eval, names[0], names[1], names[2], src);
			CK(linked(sc, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff) == T[i].req_eval, "request->eval %d in: %s", T[i].req_eval, src);
			CK(linked(sc, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) == T[i].req_exec, "request->exec %d in: %s", T[i].req_exec, src);
			CK(linked(sc, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0xff) == T[i].req_dyn, "request->call %d in: %s", T[i].req_dyn, src);
			kgenome_diag_scan_free(sc);
		}
	}
	/* variables are case sensitive: another spelling of the name is another variable and carries nothing */
	for (iter = 0; iter < 2000u; iter++) {
		char other[20];
		size_t n;

		rname(names[0]);
		n = strlen(names[0]);
		memcpy(other, names[0], n + 1u);
		for (k = 0; k < n; k++) {
			if (other[k] >= 'a' && other[k] <= 'z') {
				other[k] = (char)(other[k] - 32);
				break;
			}
			if (other[k] >= 'A' && other[k] <= 'Z') {
				other[k] = (char)(other[k] + 32);
				break;
			}
		}
		if (strcmp(other, names[0]) != 0) {
			struct kgenome_diag_scan *sc;

			snprintf(src, sizeof src, "<?php%s$%s%s=%sbase64_decode(%s'x'%s)%s;%seval(%s$%s%s)%s;", rsp(), names[0], rsp(), rsp(), rsp(), rsp(), rsp(),
				 rsp(), rsp(), other, rsp(), rsp());
			sc = scan(src);
			CK(sc && !linked(sc, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 0xff), "$%s is not $%s: %s", other, names[0], src);
			kgenome_diag_scan_free(sc);
		}
	}
}

/*
 * THE RELATIONSHIPS BETWEEN DATA AND WHAT RUNS, one row each: a value of one capability reaching another, in a given role (0xff:
 * any). Text run now is data-eval; text made into a function is data-create; a call whose callee is a value is data-call - and the
 * links differ: a decode reaches the TEXT of an eval or a create, a request or a decode or a created function reaches the CALLEE of a
 * data-call, and the arguments of a data-call are data for it.
 */
static void data_relationships(void)
{
	static const struct { const char *src; uint16_t from, to; int role; int want; } T[] = {
		{ "<?php eval(base64_decode($x));", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php create_function('', base64_decode($x));", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_CREATE, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php create_function(base64_decode($x), 'return 1;');", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_CREATE, 0xff, 0 },
		{ "<?php create_function('', $_POST['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_CREATE, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php call_user_func($_GET['f'], 1);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php call_user_func('f', $_GET['a']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0xff, 0 },
		{ "<?php $f = base64_decode($x); $f(1);", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php call_user_func(strrev(base64_decode($x)), 1);", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php call_user_func('f', base64_decode($x));", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DYNCALL, 0xff, 0 },
		/* the handle create_function returned is the callee of the call that follows */
		{ "<?php $s = create_function('', $c); $s();", KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $s = create_function('', $c); $t = $s; $t(1, 2);", KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $s = create_function('', $c); echo $s;", KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, 0xff, 0 },
		{ "<?php $s = create_function('', $c); $u = other(); $u();", KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, 0xff, 0 },
		{ "<?php function f() { $s = create_function('', $c); } function g() { $s(); }", KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, 0xff, 0 },
		/* a CLASS that is a value (data-load): the sender, a decode or a created function reaching the name of what is instantiated or
		 * called statically; the constructor's own arguments are data for it */
		{ "<?php $c = $_POST['m']; $o = new $c();", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $c = $_POST['m']; $o = new $c;", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $c = $_GET['k']; $c::run();", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $c = base64_decode($x); $o = new $c($a, $b);", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $c = 'Foo'; $o = new $c($_GET['a']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		{ "<?php $o = new Foo($_GET['a']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		{ "<?php $c = 'Foo'; $o = new $c(); $c::run($_GET['a']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		{ "<?php $o = new $t[$_GET['i']]();", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		{ "<?php $c = $_GET['c']; $o = new $c($_GET['a']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0xff, 0 },
		{ "<?php new ReflectionClass($_GET['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php new ReflectionClass('Foo');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		{ "<?php $r = new ReflectionFunction(base64_decode($x));", KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php unserialize($_COOKIE['d']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php unserialize(file_get_contents('x'));", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		{ "<?php spl_autoload_register($_GET['f']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php spl_autoload_register(function ($c) { include $c; });", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff, 0 },
		/* a request that names the function and hands it the sender's data */
		{ "<?php $_POST[0]($_POST[1]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
	};
	uint32_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		struct kgenome_diag_scan *s = scan(T[i].src);

		CK(s != NULL, "scan of %s", T[i].src);
		if (!s)
			continue;
		CK(linked(s, T[i].from, T[i].to, T[i].role) == T[i].want, "%u -> %u (role %d) wanted %d in: %s", T[i].from, T[i].to, T[i].role,
		   T[i].want, T[i].src);
		kgenome_diag_scan_free(s);
	}
}

/*
 * CODE THE SCRIPT COMPUTES, and a join of variables. A text the evaluator follows to a constant and that is handed to an eval or to
 * create_function is code: it is walked in the same scan, so what is inside it is nodes and links of the one graph. And a value that is
 * the join of variables is ALL of them, in order: an earlier evaluator answered with the last (it started the answer from nothing for
 * each variable and threw away what the join held).
 */
static void layers_and_joins(void)
{
	static const struct { const char *src; uint16_t from, to; int role; int want; } T[] = {
		/* a join of variables is every one of them */
		{ "<?php $a = 'sys'; $b = 'tem'; $n = $a . $b; $n($_GET['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff, 1 },
		{ "<?php $a = 'sy'; $b = 's'; $c = 'tem'; $n = $a . $b . $c; $n($_GET['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff, 1 },
		{ "<?php $a = 'sy'; $n = $a . 'st' . 'em'; $n($_GET['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff, 1 },
		{ "<?php $a = 'sy'; $b = 'tem'; $n = $b . $a; $n($_GET['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff, 0 },
		/* a computed text that is handed to an eval is code */
		{ "<?php eval('eval($_GET[1]);');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php $a = 'eval('; $b = '$_GET[1]);'; eval($a . $b);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php $a = 'eval('; $b = '$_GET[1]);'; $c = $a . $b; eval($c);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php create_function('', '$_GET[1]();');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php $l = 'create_function'; $s = $l('', 'eval($_POST[0]);'); $s();", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php $l = 'create_function'; $s = $l('', 'eval($_POST[0]);'); $s();", KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		/* assert runs its text too; the second argument of create_function is the code, the first is not */
		{ "<?php assert('system($_GET[1]);');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff, 1 },
		{ "<?php create_function('system($_GET[1]);', 'return 1;');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff, 0 },
		/* three layers: code inside code inside code */
		{ "<?php eval('eval(\\'eval($_GET[1]);\\');');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		/* extract() pours the request into the scope's variables: a variable read after it may hold what the sender called it (laudanum's
		 * "tiny shell that is well obfuscated"), and it overwrites one the program had set. Another scope's variables are not touched. */
		{ "<?php @extract($_REQUEST); @die($ctime($atime));", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET, 1 },
		{ "<?php extract($_POST); eval($code);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php $code = '1;'; extract($_POST); eval($code);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php extract($_GET, EXTR_PREFIX_ALL, 'p'); eval($p_code);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php extract($config); eval($code);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
		{ "<?php extract($_POST); function f() { eval($code); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
		{ "<?php function f() { extract($_POST); eval($code); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php function f() { extract($_POST); } eval($code);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
		/* a variable whose NAME is a value and that is given the request: any variable may hold it (register_globals by hand) */
		{ "<?php $k = 'a'; $$k = $_POST['x']; eval($code);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php ${$k} = $_GET[1]; eval($c);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE, 1 },
		{ "<?php $$k = 'abc'; eval($c);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
		/* NOT code: a value that is not a constant (the request is part of it), or an argument that is not the one that runs */
		{ "<?php eval($x . 'eval($_GET[1]);');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
		{ "<?php echo 'eval($_GET[1]);';", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
		{ "<?php $t = 'eval($_GET[1]);'; call_user_func('f', $t);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff, 0 },
	};
	uint32_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		struct kgenome_diag_scan *s = scan(T[i].src);

		CK(s != NULL, "scan of %s", T[i].src);
		if (!s)
			continue;
		CK(linked(s, T[i].from, T[i].to, T[i].role) == T[i].want, "%u -> %u (role %d) wanted %d in: %s", T[i].from, T[i].to, T[i].role,
		   T[i].want, T[i].src);
		kgenome_diag_scan_free(s);
	}
}

/*
 * THE CONSTANTS THE ROUTE TELLS (kgenome_diag_text_req.on_const): the right side of an assignment that is not one literal and that the
 * evaluator followed to a text - where it is in the file and what it comes to. Outermost first, none inside another, nothing from a layer of
 * code the script computes (those are not bytes of the file), and every one of them however many the file has: the work the evaluator may spend
 * grows with the text, so a long file does not lose its late constants without a word.
 */
struct told {
	uint32_t n;
	struct { uint64_t off, len; char v[64]; } c[8];
};

static void tell(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	struct told *t = u;

	if (t->n < 8u && n < 63u) {
		t->c[t->n].off = off;
		t->c[t->n].len = len;
		memcpy(t->c[t->n].v, v, n);
		t->c[t->n].v[n] = 0;
	}
	t->n++;
}

static void count_tell(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	(void)off; (void)len; (void)v; (void)n;
	++*(uint32_t *)u;
}

static struct told told_of(const char *src)
{
	struct told t = { 0 };
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = KGENOME_TEXTUAL_LANG_PHP,
					    .on_const = tell, .const_user = &t };

	kgenome_diag_scan_free(kgenome_diag_scan_text(&rq));
	return t;
}

static void constants_told(void)
{
	static const char j[] = "<?php $a = 'ab'; $b = 'cd'; $c = $a . $b;";
	struct told t = told_of(j);
	char *big;
	uint32_t i, got = 0, want = 60000u, w = 0;
	struct kgenome_diag_text_req rq;

	CK(t.n == 1u && !strcmp(t.c[0].v, "abcd") && !strncmp(j + t.c[0].off, "$a . $b", (size_t)t.c[0].len) && t.c[0].len == 7u,
	   "a join of variables, told once: %u told", t.n);
	/* one literal is not computed; a variable alone is a copy and is told (its value is the variable's) */
	t = told_of("<?php $a = 'ab'; $b = 'cd';");
	CK(t.n == 0u, "single literals are not told");
	t = told_of("<?php $a = 'ab'; $b = $a;");
	CK(t.n == 0u, "a lone variable is one token, not a join: %u", t.n);
	/* outermost first and none inside another */
	t = told_of("<?php $a = ('x' . 'y') . 'z';");
	CK(t.n == 1u && !strcmp(t.c[0].v, "xyz"), "the outer expression only: %u told", t.n);
	t = told_of("<?php $f = function () { $x = 'a' . 'b'; return $x; };");
	CK(t.n == 1u && !strcmp(t.c[0].v, "ab"), "the closure is no constant, what is inside it is: %u told", t.n);
	/* not a constant: a request in it, a call it cannot follow, a function of its own */
	CK(told_of("<?php $a = 'x' . $_GET[1];").n == 0u, "a request is no constant");
	CK(told_of("<?php $a = 'x' . foo();").n == 0u, "a call of the program's own is no constant");
	CK(told_of("<?php $a .= 'x' . 'y';").n == 0u, ".= appends: it is not the value of the variable");
	/* the text a script computes and hands to eval is code of another layer: not bytes of this file, never told */
	t = told_of("<?php eval('$q = \"a\" . \"b\";');");
	CK(t.n == 0u, "a layer's own assignments are not the file's: %u told", t.n);
	/* the work grows with the file: 60000 assignments, more than the old fixed allowance of steps could follow, are all told */
	big = malloc(60000u * 48u + 16u);
	if (big) {
		size_t pos = 0;

		memcpy(big, "<?php\n", 7);
		pos = 6;
		for (i = 0; i < want; i++)
			pos += (size_t)sprintf(big + pos, "$v%u = 'a' . 'b' . 'c' . 'd' . 'e';\n", i);
		rq = (struct kgenome_diag_text_req){ .base = (const uint8_t *)big, .size = pos, .lang = KGENOME_TEXTUAL_LANG_PHP,
						     .on_const = count_tell, .const_user = &got };
		kgenome_diag_scan_free(kgenome_diag_scan_text(&rq));
		CK(got == want, "every one of %u told, got %u", want, got);
		free(big);
	}
	(void)w;
}

/*
 * WHAT THE ROUTE MUST NOT LINK, found by running it over WordPress (1073 files, six reported, none a shell), and what it must still
 * link after each fix. A row is a program, the two capabilities, and whether one must reach the other. The pairs are the verdicts'
 * own - a request or a file read that reached something that runs.
 */
static void wordpress_regressions(void)
{
	static const struct { const char *src; uint16_t from, to; int want; } T[] = {
		/* an argument of a callback-taking call is data for the callback, not the callee */
		{ "<?php call_user_func('strlen', $_GET['a']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php call_user_func_array('strlen', array($_GET['a']));", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php $k = $_REQUEST['k']; register_shutdown_function('f', $k);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php $d = file_get_contents('a'); call_user_func('f', $d);", KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php call_user_func($_GET['f']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 1 },
		{ "<?php $f = $_POST['f']; call_user_func($f, 1);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 1 },
		/* create_function runs its SECOND argument */
		{ "<?php create_function('', $_POST['c']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_CREATE, 1 },
		{ "<?php create_function($_POST['a'], 'return 1;');", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_CREATE, 0 },
		/* an index selects an element; it is not the element: a registry looked up by a request key */
		{ "<?php $x = $s[$_POST['i']]; call_user_func($x);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php $w = $_GET['e']; $c = $t[$w]; call_user_func_array($c['cb'], $c['p']);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php $c = $_GET['a']; call_user_func($w[$c][2]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php call_user_func($w[$_GET['a']]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php eval($t[$_GET['i']]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php eval($this->items[$_GET['i']]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		/* but an element OF a request value is the request, and an array literal's elements are its value */
		{ "<?php $y = $_GET['a']; $z = $y[0]; eval($z);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php eval($_GET['a'][0]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $q = array($_GET['a'], 'b'); eval($q[0]);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		/* a variable is its function's: $b in one function is not $b in another */
		{ "<?php function a() { $b = $_GET['x']; } function b() { $b = '1;'; eval($b); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php function a() { $body = file_get_contents('x'); return $body; } function b() { $body = 3; call_user_func($f, $body); }",
		  KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php function a() { $b = $_GET['x']; eval($b); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php class C { public function m($p) { $b = $_POST['x']; return eval($b); } }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		/* the top level's variable is another one from inside a function, unless the function says it is not */
		{ "<?php $b = $_GET['x']; function a() { eval($b); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $b = $_GET['x']; function a() { global $b; eval($b); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $b = $_GET['x']; function a() { global $c, $b; eval($b); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $b = $_GET['x']; function a() { eval($GLOBALS['b']); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php function a() { $GLOBALS['g'] = $_GET['x']; } function b() { eval($GLOBALS['g']); }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $b = $_GET['x']; $f = function() use ($b) { eval($b); };", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $b = $_GET['x']; $f = function() { eval($b); };", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php function o() { $b = $_GET['x']; $f = function() use (&$b) { eval($b); }; }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php function o() { $b = $_GET['x']; function i() { eval($b); } }", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		/* the class a request names is instantiated, it is not called as code */
		{ "<?php $c = $_POST['m']; $o = new $c();", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php $c = $_POST['m']; $c();", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 1 },
		/* a number, a digest, a length is not the string it was made from; the other operand of a join still is */
		{ "<?php $a = (int)$_GET['x']; eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $a = (integer) $_GET['x']; eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $a = (bool)$_GET['x']; eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $a = md5($_GET['x']); eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $a = absint($_GET['x']); call_user_func($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, 0 },
		{ "<?php $a = strlen($_GET['x']); eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $a = intval(base64_decode($_GET['x'])); eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0 },
		{ "<?php $a = (int)$_GET['x'] . $_GET['y']; eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $a = intval($_GET['x']) . $_GET['y']; eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $a = (string)$_GET['x']; eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $a = trim($_GET['x']); eval($a);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		/* AN OVERWRITE DOES NOT CLEAR WHAT A VARIABLE WAS GIVEN: the route reads no control flow, so `$b = '1;'` in a branch that
		 * does not run would otherwise be all it takes to be rid of the request. A union of what the variable may hold. */
		{ "<?php $b = $_GET['x']; $b = '1;'; eval($b);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
		{ "<?php $b = $_GET['x']; if ($c) { $b = 'safe'; } eval($b);", KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 1 },
	};
	uint32_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		struct kgenome_diag_scan *s = scan(T[i].src);

		CK(s != NULL, "scan of %s", T[i].src);
		if (!s)
			continue;
		CK(linked(s, T[i].from, T[i].to, 0xff) == T[i].want, "%u -> %u wanted %d in: %s", T[i].from, T[i].to, T[i].want, T[i].src);
		kgenome_diag_scan_free(s);
	}
}

/*
 * THE SHELL THAT TAKES ITS PAYLOAD FROM THE BODY OF THE REQUEST (haha.php's own shape): preg_match fills $m from php://input, and
 * $m[1] is decoded twice - through a function of the script's own that is no node - and run. The graph is the request, then the
 * two decodes in the order they are applied, then the eval; and the request reaches the decode that reads $m, not the one that
 * does not.
 */
static void request_body_chain(void)
{
	struct kgenome_diag_scan *s = scan("<?php $k = 'x'; function x($t, $k) { return $t; }\n"
					   "if (@preg_match(\"/$kh(.+)$kf/\", @file_get_contents(\"php://input\"), $m) == 1) {\n"
					   "@ob_start();\n@eval(@gzuncompress(@x(@base64_decode($m[1]), $k)));\n}\n");
	uint32_t i, dec = 0, req = 0;

	CK(s != NULL, "scan");
	if (!s)
		return;
	for (i = 0; i < kgenome_diag_scan_count(s); i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		dec += h->cap == KGENOME_NUCLEO_DECODE;
		req += h->cap == KGENOME_NUCLEO_REQUEST;
	}
	CK(dec == 2u && req == 1u, "two decodes and one request, got %u and %u", dec, req);
	CK(count(s, KGENOME_NUCLEO_EVAL) == 1, "one eval");
	CK(linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DECODE, 0xff), "the request reaches a decode");
	CK(linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DECODE, 0xff), "the first decode feeds the second");
	CK(linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE), "the last decode is what the eval runs");
	kgenome_diag_scan_free(s);
}

/*
 * THE CLASSIC WAYS TO HIDE A FUNCTION NAME that need no function: built where it is used, so no marker finds it. Each is a
 * program, and what is pinned is the node it makes (the capability, and that its name was MADE), and the links the call's
 * arguments get. The ways that call str_replace, strrev and the rest are tests/unit/diag_text_built.c's: what those functions
 * DO is the engine's, handed to the route as a hook, and this lib is tested without one.
 */
static void built_names(void)
{
	static const struct { const char *src; uint16_t cap; int built; int req_to; } T[] = {
		/* $GLOBALS written and read: the name is in the array, spelled in pieces */
		{ "<?php $GLOBALS['a'] = 'sys' . 'tem'; $GLOBALS['a']($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $GLOBALS[\"n\"] = \"system\"; $f = $GLOBALS[\"n\"]; $f($_POST['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* a name read back from the global the program wrote under its plain spelling */
		{ "<?php $a = 'pass' . 'thru'; $GLOBALS['a']($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = chr(115) . chr(121) . 'stem'; $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* .= builds it a piece at a time */
		{ "<?php $n = 'sy'; $n .= 'st'; $n .= 'em'; $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* an array of names, read by an index */
		{ "<?php $fc = array('md5', 'system', 'strlen'); $fc[1]($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* a name written as it is is not BUILT (and is still the call) */
		{ "<?php $n = 'system'; $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 0, 1 },
		/* escapes in the literal are the value: \x73ystem is system */
		{ "<?php $n = \"\\x73ystem\"; $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 0, 1 },
	};
	uint32_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		struct kgenome_diag_scan *s = scan(T[i].src);

		CK(s != NULL, "scan of %s", T[i].src);
		if (!s)
			continue;
		CK(count(s, T[i].cap) == 1, "the node %u of %s in: %s", T[i].cap, T[i].cap == KGENOME_NUCLEO_EVAL ? "eval" : "exec", T[i].src);
		CK(built_node(s, T[i].cap) == T[i].built, "built %d in: %s", T[i].built, T[i].src);
		CK(linked(s, KGENOME_NUCLEO_REQUEST, T[i].cap, 0xff) == T[i].req_to, "request link %d in: %s", T[i].req_to, T[i].src);
		kgenome_diag_scan_free(s);
	}
	/* NOT a name: what depends on the program running, on something the evaluator does not know, or is not a name the table has */
	{
		static const char *const no[] = {
			"<?php $n = str_replace('k', '', $_GET['n']); echo 1;",               /* a request makes the name: no constant */
			"<?php $n = strrev('abc'); $n(1);",                                    /* a constant that is no function in the table */
			"<?php $n = unknown_fn('a'); $n(1);",                                  /* a call it does not follow */
			"<?php $n = 'sys' . $x; $n(1);",                                       /* a variable with no value */
			"<?php $fc = array('system'); $fc[5]($_GET['c']);",                    /* an index past the array */
			"<?php $n = str_replace('', 'x', 'system'); $n . 1;",                  /* never called */
		};
		uint32_t k;

		for (k = 0; k < sizeof no / sizeof no[0]; k++) {
			struct kgenome_diag_scan *s = scan(no[k]);

			CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "no exec node in: %s", no[k]);
			kgenome_diag_scan_free(s);
		}
	}
	/* WITHOUT THE HOOK a call on constants is not followed: the lib has no algorithm of its own for str_replace or strrev */
	{
		struct kgenome_diag_scan *s = scan("<?php $n = strrev('metsys'); $n($_GET['c']);");

		CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "no hook, no name built by a call");
		kgenome_diag_scan_free(s);
	}
	/* a request that made the name is still a call of whatever the request said */
	{
		struct kgenome_diag_scan *s = scan("<?php $n = str_replace('k', '', $_GET['n']); $n($_POST['c']);");

		CK(s && count(s, KGENOME_NUCLEO_DYNCALL) == 1 && linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET),
		   "the callee is the request's");
		kgenome_diag_scan_free(s);
	}
}

int main(void)
{
	struct kgenome_diag_scan *s;

	/* nesting: the decode is an argument of the eval, in the role of the value it runs */
	case_("<?php eval(base64_decode('abc'));", 1, 1, 1, 0, 0);
	s = scan("<?php eval(base64_decode('abc'));");
	CK(s && linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, KGENOME_DIAG_ROLE_VALUE), "the role is the value");
	kgenome_diag_scan_free(s);
	/* a call in between that is not a node is transparent, and so is an operator */
	case_("<?php eval(trim(strrev(gzinflate(base64_decode($x)))) . ';');", 3, 1, 1, 0, 0);
	/* assignment: the variable carries what it was given, read later */
	case_("<?php $a = base64_decode('x'); $b = $a; eval($b);", 1, 1, 1, 0, 0);
	case_("<?php $a = $_POST['x']; system($a);", 0, 0, 0, 0, 1);
	/* a request value reaching a command, an eval, a call it names */
	case_("<?php eval($_GET['c']);", 0, 1, 0, 1, 0);
	{
		/* the request names the callee and hands it an argument: a data-call, the request is its TARGET and the argument is only data */
		struct kgenome_diag_scan *c = scan("<?php $_POST[0]($_POST[1]);");

		CK(c && count(c, KGENOME_NUCLEO_DYNCALL) == 1 && count(c, KGENOME_NUCLEO_EVAL) == 0, "one data-call and no eval");
		CK(c && linked(c, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET), "the request is the target");
		kgenome_diag_scan_free(c);
	}
	/* a function name kept in a literal, joined from pieces */
	case_("<?php $f = 'sys' . 'tem'; $f($_GET['c']);", 0, 0, 0, 0, 1);
	/* NOT followed: a variable that never reached the call, a name in a comment or a literal, a call that is not in the table */
	case_("<?php $a = base64_decode('x'); $b = 1; eval($b);", 1, 1, 0, 0, 0);
	case_("<?php // eval(base64_decode('x'))\n echo 'eval(base64_decode(x))'; md5('x');", 0, 0, 0, 0, 0);
	/* the scan of a language the route does not serve has no nodes, and is not a failure (js was used here until it got a row: see tests/lib/genome/diag_text_langs.c) */
	{
		struct kgenome_diag_text_req rq = { .base = (const uint8_t *)"eval(base64_decode('x'));", .size = 25u, .lang = KGENOME_TEXTUAL_LANG_NONE };

		s = kgenome_diag_scan_text(&rq);
		CK(s && kgenome_diag_scan_count(s) == 0, "a language with no table: no nodes");
		kgenome_diag_scan_free(s);
	}
	CK(kgenome_diag_scan_text(NULL) == NULL, "no request");
	/* the names: each once, as the table spells them */
	{
		struct names nm = { .n = 0 };
		const char *src = "<?php eval(base64_decode($_GET['a'])); eval(Base64_Decode($x)); md5(1);";

		kgenome_diag_text_names((const uint8_t *)src, strlen(src), KGENOME_TEXTUAL_LANG_PHP, NULL, collect, &nm);
		CK(nm.n == 3, "three distinct names, got %d", nm.n);
	}
	random_names_and_spacing();
	request_body_chain();
	data_relationships();
	layers_and_joins();
	constants_told();
	wordpress_regressions();
	built_names();
	printf("diag text: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
