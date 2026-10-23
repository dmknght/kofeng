/*
 * diag_text_langs_golden - the fixture diagnoses (tests/sigs/diagnoses/php_*.c: capabilities, no function named, so they apply to any language whose
 * nodes the TEXT route makes) against small SYNTHETIC scripts of each language the route reads through its profile row, through the whole engine:
 * the file is typed (a shebang, or the page directive), read by its lexer, its calls are the file's imports (the gate) and its nodes and links are
 * the scan. Each row is a diagnose, a text, and whether it must fire - the "must not" half is as much of the pin as the "must".
 *
 * ALSO PINNED THROUGH THE ENGINE, because what they guard is engine-side: the route reads the script and not its normalised view for every language
 * but php (a python view has no indentation, so every function's variables merge: the rows `view`). The statement-call languages are in
 * diag_text_stmt_golden.c.
 *
 * Every text begins with padding: a script of a few dozen bytes is not read as one.
 */

#include "diag_text_fire.h"


#define PYH "#!/usr/bin/env python3\n"
#define JSH "#!/usr/bin/env node\n"
#define RBH "#!/usr/bin/env ruby\n"
#define LUH "#!/usr/bin/env lua\n"
#define PLH "#!/usr/bin/perl\n"
#define JSPH "<%@ page import=\"java.io.*\" %>\n"
#define AXH "<%@ Page Language=\"C#\" %>\n"

static const struct row rows[] = {
	/* ---- python ---- */
	{ "php_request_exec", PYH "# padding padding padding padding padding padding padding\nimport os\nfrom flask import request\ndef run():\n    cmd = request.args.get('c')\n    os.system(cmd)\n", 1 },
	{ "php_request_exec", PYH "# padding padding padding padding padding padding padding\nimport subprocess\nsubprocess.call(request.form['c'], shell=True)\n", 1 },
	{ "php_request_exec", PYH "# padding padding padding padding padding padding padding\nimport os\ncmd = request.args.get('c')\nos.system('uptime')\n", 0 },
	{ "php_request_eval", PYH "# padding padding padding padding padding padding padding\neval(request.args['code'])\n", 1 },
	{ "php_request_eval", PYH "# padding padding padding padding padding padding padding\neval('1 + 1')\n", 0 },
	{ "php_decode_eval", PYH "# padding padding padding padding padding padding padding\nimport base64\nexec(base64.b64decode(blob))\n", 1 },
	{ "php_decode_eval", PYH "# padding padding padding padding padding padding padding\nimport base64\nd = base64.b64decode(blob)\nprint(d)\nexec('print(1)')\n", 0 },
	{ "php_request_call", PYH "# padding padding padding padding padding padding padding\nf = request.args.get('f')\nf(1)\n", 1 },
	{ "php_request_call", PYH "# padding padding padding padding padding padding padding\nf = print\nf(request.args.get('x'))\n", 0 },
	{ "php_built_eval", PYH "# padding padding padding padding padding padding padding\nn = 'ev' + 'al'\nglobals()[n](x)\n", 1 },
	{ "php_built_eval", PYH "# padding padding padding padding padding padding padding\nn = 'print'\nglobals()[n](x)\n", 0 },
	/* two functions that share a variable name: the request is in one, the command in the other */
	{ "php_request_exec", PYH "# padding padding padding padding padding padding padding\n\n# the first\ndef a():\n    cmd = request.args.get('c')\n    return len(cmd)\n\n\n# the second\ndef b():\n    cmd = 'uptime'\n    os.system(cmd)\n", 0 },

	/* ---- javascript (node) ---- */
	{ "php_request_exec", JSH "// padding padding padding padding padding padding padding\nconst cp = require('child_process');\napp.get('/x', (req, res) => {\n  cp.exec(req.query.c)\n})\n", 1 },
	{ "php_request_exec", JSH "// padding padding padding padding padding padding padding\nrequire('child_process').execSync(req.body.cmd);\n", 1 },
	{ "php_request_exec", JSH "// padding padding padding padding padding padding padding\nconst cp = require('child_process');\ncp.exec('uptime'); console.log(req.query.c);\n", 0 },
	{ "php_request_eval", JSH "// padding padding padding padding padding padding padding\neval(req.query.code);\n", 1 },
	{ "php_request_eval", JSH "// padding padding padding padding padding padding padding\nvar t = req.query.x;\nfunction a(t) { return eval(t) }\n", 0 },
	{ "php_decode_eval", JSH "// padding padding padding padding padding padding padding\nvar d = atob(req.query.p)\neval(d)\n", 1 },
	{ "php_decode_eval", JSH "// padding padding padding padding padding padding padding\nvar d = atob(x)\nconsole.log(d)\neval(y)\n", 0 },
	{ "php_request_call", JSH "// padding padding padding padding padding padding padding\nwindow[req.query.f](1);\n", 1 },
	{ "php_request_call", JSH "// padding padding padding padding padding padding padding\nvar f = function (s) { return req.query.f }\nf(1)\n", 0 },
	{ "php_built_eval", JSH "// padding padding padding padding padding padding padding\nvar n = 'ev' + 'al';\nwindow[n](x);\n", 1 },
	{ "php_decode_call", JSH "// padding padding padding padding padding padding padding\nvar f = function (s) { return atob(s) }\nf(x)\n", 0 },

	/* ---- ruby ---- */
	{ "php_request_exec", RBH "# padding padding padding padding padding padding padding\ncmd = params[:c]\nsystem(cmd)\n", 1 },
	{ "php_request_exec", RBH "# padding padding padding padding padding padding padding\ndef a\n  c = params[:c]\n  c.size\nend\n\ndef b\n  c = 'ls'\n  system(c)\nend\n", 0 },
	{ "php_request_eval", RBH "# padding padding padding padding padding padding padding\neval(params[:code])\n", 1 },
	{ "php_decode_eval", RBH "# padding padding padding padding padding padding padding\nrequire 'base64'\neval(Base64.decode64(blob))\n", 1 },
	{ "php_request_call", RBH "# padding padding padding padding padding padding padding\nsend(params[:m], 1)\n", 1 },
	{ "php_request_call", RBH "# padding padding padding padding padding padding padding\nsend(:puts, params[:m])\n", 0 },

	/* ---- lua ---- */
	{ "php_request_exec", LUH "-- padding padding padding padding padding padding padding\nlocal c = ngx.var.arg_c\nos.execute(c)\n", 1 },
	{ "php_request_exec", LUH "-- padding padding padding padding padding padding padding\nlocal c = ngx.var.arg_c\nlocal d = 'ls'\nos.execute(d)\n", 0 },
	{ "php_decode_create", LUH "-- padding padding padding padding padding padding padding\nlocal code = mime.unb64(blob)\nloadstring(code)()\n", 1 },
	{ "php_request_call", LUH "-- padding padding padding padding padding padding padding\nlocal p = ngx.req.get_uri_args()\n_G[p.f](1)\n", 1 },

	/* ---- perl: the bracketed calls, and eval {} which is no eval of text ---- */
	{ "php_request_exec", PLH "# padding padding padding padding padding padding padding\nmy $c = $ENV{QUERY_STRING};\nsystem($c);\n", 1 },
	{ "php_request_eval", PLH "# padding padding padding padding padding padding padding\neval($ENV{HTTP_COOKIE});\n", 1 },
	{ "php_request_eval", PLH "# padding padding padding padding padding padding padding\nmy $c = $ENV{QUERY_STRING};\neval { system(\"ls\") };\n", 0 },
	{ "php_decode_eval", PLH "# padding padding padding padding padding padding padding\nuse MIME::Base64;\nmy $code = decode_base64($blob);\neval($code);\n", 1 },
	{ "php_decode_eval", PLH "# padding padding padding padding padding padding padding\nuse MIME::Base64;\nmy $r = eval { decode_base64($blob) };\nprint $r;\n", 0 },

	/* ---- java (jsp) ---- */
	{ "php_request_exec", JSPH "<%\nString c = request.getParameter(\"c\");\nRuntime.getRuntime().exec(c);\n%>\n<html>padding padding padding padding</html>\n", 1 },
	{ "php_request_exec", JSPH "<% new ProcessBuilder(\"sh\", \"-c\", request.getParameter(\"c\")).start(); %>\n<html>padding padding padding padding</html>\n", 1 },
	{ "php_request_exec", JSPH "<% String c = request.getParameter(\"c\"); out.println(c); Runtime.getRuntime().exec(\"ls\"); %>\n<html>padding padding</html>\n", 0 },
	{ "php_request_load", JSPH "<% Class c = Class.forName(request.getParameter(\"k\")); %>\n<html>padding padding padding padding</html>\n", 1 },
	{ "php_decode_eval", JSPH "<% ScriptEngine e = m.getEngineByName(\"js\");\ne.eval(new String(Base64.getDecoder().decode(blob))); %>\n<html>padding padding padding padding</html>\n", 1 },

	/* ---- c# (aspx) ---- */
	{ "php_request_exec", AXH "<script runat=\"server\">\nvoid Page_Load(object s, EventArgs e) {\n  string c = Request.Form[\"c\"];\n  Process.Start(c);\n}\n</script>\n", 1 },
	{ "php_request_exec", AXH "<script runat=\"server\">\nvoid Page_Load(object s, EventArgs e) { string c = Request.Form[\"c\"]; Response.Write(c); Process.Start(\"calc\"); }\n</script>\n", 0 },
	{ "php_decode_load", AXH "<script runat=\"server\">\nvoid Page_Load(object s, EventArgs e) { Assembly.Load(Convert.FromBase64String(blob)); }\n</script>\n", 1 },
};

/*
 * `view`: a python script written the way people write one - blank lines, comments, a function after another - has a normalised view (the form takes
 * those out, and the indentation with them). The route reads the script; read on the view, the two functions below are one scope and the request of
 * the first reaches the command of the second. Nothing of the set may fire on it (pdb.py of the corpus did, on its view).
 */
static const char view_py[] = PYH
	"# padding padding padding padding padding padding padding padding\n"
	"\n"
	"# the first function\n"
	"def first():\n"
	"    code = request.args.get('c')\n"
	"    return len(code)\n"
	"\n"
	"\n"
	"# the second function\n"
	"def second():\n"
	"    code = compile('1', 'f', 'exec')\n"
	"    cmd = 'uptime'\n"
	"    os.system(cmd)\n"
	"    return code\n";

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("diag text langs golden: cannot open the test database\n");
		return 2;
	}
	fire_rows(rows, sizeof rows / sizeof rows[0]);
	CK(fires_any(view_py) == 0);
	/* a plain script of each language has no verdict at all */
	CK(fires_any(PYH "# padding padding padding padding padding padding padding\nprint('hello')\n") == 0);
	CK(fires_any(JSH "// padding padding padding padding padding padding padding\nconsole.log('hello');\n") == 0);
	CK(fires_any(RBH "# padding padding padding padding padding padding padding\nputs 'hello'\n") == 0);
	CK(fires_any(LUH "-- padding padding padding padding padding padding padding\nprint('hello')\n") == 0);
	CK(fires_any(PLH "# padding padding padding padding padding padding padding\nprint \"hello\";\n") == 0);
	printf("diag text langs golden: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
