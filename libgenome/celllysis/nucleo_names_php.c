/*
 * nucleo_names_php.c - what a PHP name means, in the vocabulary a native program's imports are read in.
 *
 * A script has no import table and no system call: what it asks of the system it asks by calling a function that the
 * runtime provides, so the names here are the runtime's. PHP does not care about the case of a function name (`fold`), and
 * a name is written the way the language spells it with nothing before it ("_GET" is `$_GET`, "include" is the construct).
 *
 * WHAT IS HERE IS THE EVIDENCE A SHELL IS MADE OF, not the language's surface. The rule the native vocabulary keeps - a name
 * is a row only when it carries a claim the ordinary program does not make - holds here too, and what it kept out is
 * written down at the end. Where one function is two capabilities by its arguments (preg_replace with /e, fopen of a url)
 * the weaker one is named: the table holds names, and an argument is the matcher's.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: bytes made out of other bytes, with no key. The step between where a payload is kept and where it runs.
	 * strrev and str_rot13 are here because that is what they are used for in a shell (an obfuscated name, a hidden
	 * payload) and the rest of the program does not call them.
	 */
	{ .name = "base64_decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "convert_uudecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "str_rot13", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "strrev", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "hex2bin", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "gzinflate", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "gzuncompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "gzdecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib_decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "bzdecompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "urldecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "rawurldecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "quoted_printable_decode", .cap = KGENOME_NUCLEO_DECODE },
	/* With a key: the same step, and the weaker word is what a rule about "a decode" must not miss. */
	{ .name = "openssl_decrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "openssl_encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "mcrypt_decrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "mcrypt_encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * CODE EXECUTION IS NOT COMMAND EXECUTION, and the table keeps them apart on purpose. EVAL and CREATE (and DYNCALL, DYNLOAD,
	 * LIB_OPEN below) hand text or a name to the PHP runtime, which runs it inside the script's own process with the script's own
	 * rights: nothing new starts. EXEC_IMAGE (system, exec, ... in the PROCESS block) asks the operating system to start another
	 * program. A shell is made of either, a rule about one must not be satisfied by the other, and the verdict names say which.
	 * What is not defined yet is listed at the end of the table.
	 *
	 * EVAL: text run as code, now. eval and assert take the text.
	 * CREATE: text that becomes a function, called later by the handle it is given: create_function.
	 * DYNCALL: a call whose callee is a STRING, which is how a name kept in a literal is called without ever being written. The
	 * row "(dynamic)" is not a PHP name: it is what `$f(...)` is when $f is not a name the program wrote (the sender chose it, a
	 * decode made it, create_function returned it), so that the names a script "imports" say what the walk found.
	 * DYNLOAD: a class, an object or a loader named by a value. The constructors of the reflection classes take the NAME of what they
	 * reflect, and from there newInstance / invoke run it; unserialize instantiates the classes its data names; an autoloader is
	 * code the runtime runs when it meets a class it does not know. A library does all of these for its own routing, and so does a
	 * backdoor - that is why the word exists and is not a verdict. The row "(load)" is `new $cls` and `$cls::f()` with $cls a value.
	 */
	{ .name = "eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "assert", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "create_function", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "call_user_func", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "call_user_func_array", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "forward_static_call", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "forward_static_call_array", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "register_shutdown_function", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "ReflectionClass", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "ReflectionObject", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "ReflectionMethod", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "ReflectionFunction", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "unserialize", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "spl_autoload_register", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "spl_autoload_call", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/* Code loaded from a file: the same act as a library load, and the operand is what makes it a shell. */
	{ .name = "include", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "include_once", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "require", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "require_once", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "dl", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/* REQUEST: what the sender chose. A variable and not a call. */
	{ .name = "_GET", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "_POST", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "_REQUEST", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "_COOKIE", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "_FILES", .cap = KGENOME_NUCLEO_REQUEST },
	/* PROCESS: the native word is proc-start for every one of them. */
	{ .name = "system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "shell_exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "passthru", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "proc_open", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "pcntl_exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "pcntl_fork", .cap = KGENOME_NUCLEO_SPAWN },
	/* FILE: read, write, delete, rename, permissions, times. A shell's file manager is these and nothing else. */
	{ .name = "fopen", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "file_get_contents", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "file", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "readfile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "fpassthru", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "highlight_file", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "show_source", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "file_put_contents", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fwrite", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fputs", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "move_uploaded_file", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "copy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "rmdir", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "chgrp", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "touch", .cap = KGENOME_NUCLEO_TIMESTOMP },
	/* NETWORK: sockets as the language gives them, and curl as the HTTP layer above. */
	{ .name = "fsockopen", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "pfsockopen", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "stream_socket_client", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "stream_socket_server", .cap = KGENOME_NUCLEO_NET_LISTEN },
	/* The stream API's other half of a server and the other direction of a client: the rows above have socket_accept and socket_read/write without them.
	 * [Unverified against a corpus: none of the shells here uses these four; they are the documented counterparts of rows that are here.] */
	{ .name = "stream_socket_accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "socket_create_listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "stream_socket_recvfrom", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "stream_socket_sendto", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "socket_create", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "socket_connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "socket_bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "socket_listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "socket_accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "socket_read", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "socket_recv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "socket_write", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "socket_send", .cap = KGENOME_NUCLEO_NET_WRITE },
	/*
	 * Every lookup the language has is the same act as gethostbyname, and a resolver tool offered through the web server (laudanum's dns.php and host.php:
	 * `dns_get_record($_POST[..])`, `gethostbyaddr($_POST[..])`) uses the others: 4 of the 76 shells here call gethostbyaddr, 2 dns_get_record, and none
	 * of the 13,392 + 1,073 benign files links one of them to the request.
	 */
	{ .name = "gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "gethostbynamel", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "gethostbyaddr", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns_get_record", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "checkdnsrr", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns_check_record", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "getmxrr", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns_get_mx", .cap = KGENOME_NUCLEO_DNS },
	/* An ftp connection is a connection (ftp brute forcers in the c99 and alfa families: 8 of the 76 call ftp_connect). */
	{ .name = "ftp_connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ftp_ssl_connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "curl_init", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "curl_exec", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	/*
	 * LEFT OUT, because the name is not the evidence (the native table keeps the same rule): mail, header, session_start,
	 * ini_set, set_time_limit, error_reporting (every script calls them; what a shell does with them is an argument),
	 * scandir, glob, opendir (every file lister), md5, sha1, crc32, chr, ord (every program), phpinfo, php_uname,
	 * getenv, posix_* (host identity), preg_replace (eval only with the /e flag, which an argument decides) and
	 * array_map, usort, array_filter (callbacks, but ordinary ones far more often than not).
	 *
	 * NOT DEFINED YET (open; each needs a review before it becomes a row, see the nucleo review list in the owner's issue file):
	 *  - preg_replace with the /e modifier runs the replacement as code. The table names the weaker capability (a regex), because
	 *    the modifier is an argument. [Unverified here] PHP removed /e in 7.0, so only older scripts use it. Not told apart from
	 *    an ordinary preg_replace by any row.
	 *  - assert runs its argument as code only when that argument is a string; given an expression it does not. [Unverified here]
	 *    PHP 8 no longer evaluates a string given to assert. The row is EVAL for the name, whatever the argument is.
	 *  - include/require are LIB_OPEN. They run the PHP code of a file, which is code execution from a file; what makes one a
	 *    backdoor is the operand (a request value, an uploaded file, a decoded path), and that is the matcher's, not the row's.
	 *  - A callback named by a STRING runs that function: array_map('system', ...), usort, array_filter, array_walk,
	 *    preg_replace_callback, ob_start, set_error_handler, register_tick_function. The callee can be a command runner or an
	 *    eval wrapper, and the row does not say which parameter of which function takes the callee. DYNCALL covers the call_user_func
	 *    family only.
	 *  - Whether EVAL and CREATE should be one capability. They differ in when the code runs (now / at the later call of the
	 *    handle) and the relations say so today (create -> call); left as two.
	 *  - A name for "code execution" as one verdict family spanning EVAL, CREATE, DYNCALL, DYNLOAD and LIB_OPEN, beside the
	 *    command-execution family (EXEC_IMAGE, SPAWN). The disease names carry "exec" for both today (script/decode-exec is the
	 *    command one; the eval ones are the "-eval" fixtures).
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_php = {
	.target = KGENOME_NUCLEO_T_PHP, .fold = 1, .row = rows, .n = sizeof rows / sizeof rows[0]
};
