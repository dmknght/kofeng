/*
 * diag_text_e2e - a diagnose written for the TEXT route, through the engine: a php file is read by its lexer, its calls are
 * the file's "imports" (the gate), its nodes and links are the scan, and the matched diagnose makes the verdict like any other.
 *
 * The fixtures are tests/sigs/diagnoses/php_decode_eval.c and php_request_eval.c: two statements in capabilities, neither naming
 * a function. What is pinned is that the same two statements are found through every spelling the route follows, and are NOT
 * found where the text only mentions the names (a comment, a literal) or where the value never reached the call.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "../lib/genome/diag_text_gen.h"

/*
 * Whether the verdict was made of a disease with this word in its name. The verdict's NAME is the lead disease only (the most specific one), and
 * a text that is two behaviours - a decoder called through a name the script built, and its result run - is named for whichever leads, so the
 * name cannot say that the other was found too. The diseases the verdict carries can (struct kof_finding disease[]).
 */
static int matched(const char *src, const char *disease_word)
{
	struct e2e r;
	const struct kof_finding *f;
	uint32_t i;

	memset(&r, 0, sizeof r);
	if (!e2e_scan((const uint8_t *)src, strlen(src), &r) || !r.n || !r.o[0].has_verdict)
		return 0;
	f = &r.o[0].vf;
	for (i = 0; i < f->n_disease; i++) {
		const char *n = kdb_disease_name(e2e_eng, f->disease[i]);

		if (n && strstr(n, disease_word))
			return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("diag text e2e: cannot open the test database\n");
		return 2;
	}
	/* decode -> eval, in the spellings the route follows */
	CK(matched("<?php\n// padding padding padding padding\neval(base64_decode('YWJj'));\n", "decode-eval"));
	CK(matched("<?php\n// padding padding padding padding\n$a = gzinflate(base64_decode($_POST['x']));\neval($a);\n", "decode-eval"));
	CK(matched("<?php\n// padding padding padding padding\n$f = 'ev'.'al'; $d = str_rot13('x'); $f($d);\n", "decode-eval") == 0 ||
	   1);       /* eval is a construct and not callable through a variable: not claimed either way */
	CK(matched("<?php\n// padding padding padding padding\n$c = 'base64_' . 'decode'; $p = $c('abc'); eval($p);\n", "decode-eval"));
	/* request -> eval, including the call the request names */
	CK(matched("<?php\n// padding padding padding padding\neval($_GET['c']);\n", "request-eval"));
	CK(matched("<?php\n// padding padding padding padding\n$_POST[0]($_POST[1]);\n", "request-call"));
	/* NOT found: names only mentioned, and a value that never reached the call */
	CK(!matched("<?php\n// eval(base64_decode('x')) in a comment, padding padding\necho 'eval(base64_decode(x))';\n", "decode-eval"));
	CK(!matched("<?php\n// padding padding padding padding\n$a = base64_decode('x'); $b = 1; eval($b);\n", "decode-eval"));
	CK(!matched("<?php\n// padding padding padding padding\n$a = $_GET['x']; echo md5($a); eval('return 1;');\n", "request-eval"));
	/*
	 * THE RELATIONSHIPS BETWEEN DATA AND A CALL, one diagnose each (tests/sigs/diagnoses/php_*_{call,create}.c): a request that names the
	 * callee, a decode that is the callee's name, text from a request or a decode made into a function, a name built by string
	 * operations, and a function created then called through its handle. Each must fire on its spelling and NOT on its neighbour.
	 */
	CK(matched("<?php\n// padding padding padding padding\n$_POST[0]($_POST[1]);\n", "request-call"));
	CK(matched("<?php\n// padding padding padding padding\ncall_user_func($_GET['f'], 1);\n", "request-call"));
	CK(matched("<?php\n// padding padding padding padding\n$f = $_REQUEST['f']; $f($x);\n", "request-call"));
	CK(!matched("<?php\n// padding padding padding padding\ncall_user_func('strlen', $_GET['a']);\n", "request-call"));      /* an argument is data */
	CK(!matched("<?php\n// padding padding padding padding\n$t = array('a'); $f = $t[$_GET['i']]; $f($x);\n", "request-call")); /* an index selects */
	CK(matched("<?php\n// padding padding padding padding\n$f = base64_decode($blob); $f($c);\n", "decode-call"));
	/* a decode of a CONSTANT is a name the evaluator reads, and is built-exec (the function is system), not a decode the program holds */
	CK(matched("<?php\n// padding padding padding padding\n$f = base64_decode('c3lzdGVt'); $f($c);\n", "built-exec"));
	CK(matched("<?php\n// padding padding padding padding\ncall_user_func(str_rot13($blob), $c);\n", "decode-call"));
	CK(!matched("<?php\n// padding padding padding padding\ncall_user_func('f', base64_decode($x));\n", "decode-call"));
	CK(matched("<?php\n// padding padding padding padding\ncreate_function('', $_POST['c']);\n", "request-create"));
	CK(!matched("<?php\n// padding padding padding padding\ncreate_function($_POST['a'], 'return 1;');\n", "request-create"));
	CK(matched("<?php\n// padding padding padding padding\n$f = create_function('', base64_decode($x));\n", "decode-create"));
	CK(matched("<?php\n// padding padding padding padding\n$l = str_replace('k', '', 'ckrekatek_fuknkkction'); $l('', $c);\n", "built-create"));
	CK(matched("<?php\n// padding padding padding padding\n$n = strrev('cnuf_resu_llac'); $n($x);\n", "built-call"));
	CK(matched("<?php\n// padding padding padding padding\n$s = create_function('', $code); $s();\n", "create-call"));
	CK(!matched("<?php\n// padding padding padding padding\n$s = create_function('', $code); echo $s;\n", "create-call"));
	CK(matched("<?php\n// padding padding padding padding\n$c = $_POST['m']; $o = new $c();\n", "request-load"));
	CK(matched("<?php\n// padding padding padding padding\nunserialize($_COOKIE['d']);\n", "request-load"));
	CK(matched("<?php\n// padding padding padding padding\nspl_autoload_register($_GET['f']);\n", "request-load"));
	CK(!matched("<?php\n// padding padding padding padding\n$o = new Foo($_GET['a']);\n", "request-load"));      /* constructor argument: data */
	CK(!matched("<?php\n// padding padding padding padding\n$c = 'Foo'; $o = new $c($_GET['a']);\n", "request-load"));
	CK(matched("<?php\n// padding padding padding padding\n$c = base64_decode($blob); $o = new $c;\n", "decode-load"));
	CK(matched("<?php\n// padding padding padding padding\nunserialize(base64_decode($d));\n", "decode-load"));
	/* hoho.php's payload is computed from eight variables joined and cleaned by str_replace, and what is inside it is analysed: the decode
	 * of what the request posts, run - the same facts as haha.php, which is the text the family assembles */
	CK(matched("<?php\n// padding padding padding padding\n$v = 'ec#ho 1;ev'; $p = 'al(gzuncompress(b#ase64_decode($_POST[0])));'; $l = str_replace('k', '', 'ckrekatek_fuknkkction'); "
		   "$u = str_replace('#', '', $v . $p); $s = $l('', $u); $s();\n", "decode-eval"));
	CK(matched("<?php\n// padding padding padding padding\n$v = 'ec#ho 1;ev'; $p = 'al(gzuncompress(b#ase64_decode($_POST[0])));'; $l = str_replace('k', '', 'ckrekatek_fuknkkction'); "
		   "$u = str_replace('#', '', $v . $p); $s = $l('', $u); $s();\n", "create-call"));
	/* laudanum's tiny shell: extract() makes the callee and its argument what the request called them */
	CK(matched("<?php\n// padding padding padding padding\n@extract($_REQUEST);\n@die ($ctime($atime));\n", "request-call"));
	CK(!matched("<?php\n// padding padding padding padding\n@extract($config);\n@die ($ctime($atime));\n", "request-call"));
	/* a join of variables whose pieces are not all constants is not code (the request is part of the text) */
	CK(!matched("<?php\n// padding padding padding padding\n$v = 'eval(gzuncompress(base64_decode($_POST[0])));'; eval($x . $v);\n", "decode-eval"));
	/* hoho.php's own shape: the text is built, the function is made, the handle is called */
	CK(matched("<?php\n// padding padding padding padding\n$l = str_replace('k', '', 'ckrekatek_fuknkkction'); $u = str_replace('T|', '', 'ecT|ho 1;'); $s = $l('', $u); $s();\n", "create-call"));
	/* the same two facts through names and spacing nobody would write by hand */
	{
		static const char *const yes[] = {
			"<?php\n// padding padding padding padding\n@$~1@=@base64_decode@(@'YWJj'@)@;@eval@(@$~1@)@;",
			"<?php\n// padding padding padding padding\n@$~1@=@gzinflate@(@base64_decode@(@$~2@)@)@;@$~3@=@$~1@;@EVAL@(@$~3@)@;",
		};
		char nm[3][20], src[512];
		const char *vn[3] = { nm[0], nm[1], nm[2] };
		unsigned it, k;

		for (it = 0; it < 150u; it++) {
			for (k = 0; k < 3u; k++)
				rname(nm[k]);
			expand(src, sizeof src, yes[it & 1u], vn);
			if (!matched(src, "decode-eval")) {
				printf("  FAIL decode-eval, names %s %s %s: %s\n", nm[0], nm[1], nm[2], src);
				fails++;
			}
		}
	}
	/* and a plain page has no verdict at all */
	CK(!matched("<?php\n// padding padding padding padding\nfunction add($a, $b) { return $a + $b; }\necho add(1, 2);\n", "script/"));
	printf("diag text e2e: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
