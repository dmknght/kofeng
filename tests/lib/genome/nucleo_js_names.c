/*
 * nucleo_js_names - the rows of the JavaScript table (node and the browser), and the names it keeps out
 * (libgenome/celllysis/nucleo_names_js.c): every row resolves to its capability and gives its own name back through its id, the
 * capability of every row is counted (a row moved to another word, added or dropped changes a count), the names the table keeps
 * OUT on purpose resolve to nothing, and the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every JavaScript program there is. Each is pinned here with
 * the file count that decided it - in the 3286 benign / 1356 malware files the table was measured on (the measurement and its
 * limits are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_JS

int main(void)
{
	static const struct nn_is is[] = {
		{ "atob", KGENOME_NUCLEO_DECODE },
		{ "window.atob", KGENOME_NUCLEO_DECODE },
		{ "unescape", KGENOME_NUCLEO_DECODE },
		{ "zlib.inflateSync", KGENOME_NUCLEO_DECODE },
		{ "zlib.gunzipSync", KGENOME_NUCLEO_DECODE },
		{ "zlib.unzipSync", KGENOME_NUCLEO_DECODE },
		{ "zlib.inflateRawSync", KGENOME_NUCLEO_DECODE },
		{ "pako.inflate", KGENOME_NUCLEO_DECODE },
		{ "crypto.createDecipheriv", KGENOME_NUCLEO_CRYPTO },
		{ "crypto.createDecipher", KGENOME_NUCLEO_CRYPTO },
		{ "crypto.createCipheriv", KGENOME_NUCLEO_CRYPTO },
		{ "CryptoJS.AES.decrypt", KGENOME_NUCLEO_CRYPTO },
		{ "CryptoJS.AES.encrypt", KGENOME_NUCLEO_CRYPTO },
		{ "eval", KGENOME_NUCLEO_EVAL },
		{ "window.eval", KGENOME_NUCLEO_EVAL },
		{ "execScript", KGENOME_NUCLEO_EVAL },
		{ "vm.runInNewContext", KGENOME_NUCLEO_EVAL },
		{ "vm.runInThisContext", KGENOME_NUCLEO_EVAL },
		{ "vm.runInContext", KGENOME_NUCLEO_EVAL },
		{ "Function", KGENOME_NUCLEO_CREATE },
		{ "vm.Script", KGENOME_NUCLEO_CREATE },
		{ "vm.compileFunction", KGENOME_NUCLEO_CREATE },
		{ "Reflect.apply", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "importScripts", KGENOME_NUCLEO_LIB_OPEN },
		{ "process.dlopen", KGENOME_NUCLEO_LIB_OPEN },
		{ "ffi.Library", KGENOME_NUCLEO_LIB_OPEN },
		{ "req.query", KGENOME_NUCLEO_REQUEST },
		{ "req.body", KGENOME_NUCLEO_REQUEST },
		{ "req.params", KGENOME_NUCLEO_REQUEST },
		{ "req.cookies", KGENOME_NUCLEO_REQUEST },
		{ "req.files", KGENOME_NUCLEO_REQUEST },
		{ "request.query", KGENOME_NUCLEO_REQUEST },
		{ "request.body", KGENOME_NUCLEO_REQUEST },
		{ "request.params", KGENOME_NUCLEO_REQUEST },
		{ "request.payload", KGENOME_NUCLEO_REQUEST },
		{ "location.hash", KGENOME_NUCLEO_REQUEST },
		{ "location.search", KGENOME_NUCLEO_REQUEST },
		{ "document.cookie", KGENOME_NUCLEO_REQUEST },
		{ "window.name", KGENOME_NUCLEO_REQUEST },
		{ "child_process.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "child_process.execSync", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "child_process.spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "child_process.spawnSync", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "child_process.execFile", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "child_process.execFileSync", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "child_process.fork", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "fs.readFile", KGENOME_NUCLEO_FILE_OPEN },
		{ "fs.readFileSync", KGENOME_NUCLEO_FILE_OPEN },
		{ "fs.createReadStream", KGENOME_NUCLEO_FILE_OPEN },
		{ "fs.writeFile", KGENOME_NUCLEO_WRITE },
		{ "fs.writeFileSync", KGENOME_NUCLEO_WRITE },
		{ "fs.appendFile", KGENOME_NUCLEO_WRITE },
		{ "fs.appendFileSync", KGENOME_NUCLEO_WRITE },
		{ "fs.createWriteStream", KGENOME_NUCLEO_WRITE },
		{ "fs.copyFile", KGENOME_NUCLEO_WRITE },
		{ "fs.copyFileSync", KGENOME_NUCLEO_WRITE },
		{ "fs.unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "fs.unlinkSync", KGENOME_NUCLEO_FILE_DELETE },
		{ "fs.rm", KGENOME_NUCLEO_FILE_DELETE },
		{ "fs.rmSync", KGENOME_NUCLEO_FILE_DELETE },
		{ "fs.rmdir", KGENOME_NUCLEO_FILE_DELETE },
		{ "fs.rmdirSync", KGENOME_NUCLEO_FILE_DELETE },
		{ "fs.rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "fs.renameSync", KGENOME_NUCLEO_FILE_RENAME },
		{ "fs.chmod", KGENOME_NUCLEO_PERM_SET },
		{ "fs.chmodSync", KGENOME_NUCLEO_PERM_SET },
		{ "fs.chown", KGENOME_NUCLEO_PERM_SET },
		{ "fs.chownSync", KGENOME_NUCLEO_PERM_SET },
		{ "fs.utimes", KGENOME_NUCLEO_TIMESTOMP },
		{ "fs.utimesSync", KGENOME_NUCLEO_TIMESTOMP },
		{ "net.Socket", KGENOME_NUCLEO_NET_OPEN },
		{ "dgram.createSocket", KGENOME_NUCLEO_NET_OPEN },
		{ "net.connect", KGENOME_NUCLEO_NET_CONNECT },
		{ "net.createConnection", KGENOME_NUCLEO_NET_CONNECT },
		{ "tls.connect", KGENOME_NUCLEO_NET_CONNECT },
		{ "WebSocket", KGENOME_NUCLEO_NET_CONNECT },
		{ "net.createServer", KGENOME_NUCLEO_NET_LISTEN },
		{ "http.request", KGENOME_NUCLEO_HTTP_FETCH },
		{ "http.get", KGENOME_NUCLEO_HTTP_FETCH },
		{ "https.request", KGENOME_NUCLEO_HTTP_FETCH },
		{ "https.get", KGENOME_NUCLEO_HTTP_FETCH },
		{ "fetch", KGENOME_NUCLEO_HTTP_FETCH },
		{ "XMLHttpRequest", KGENOME_NUCLEO_HTTP_OPEN },
		{ "XMLHttpRequest.open", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "XMLHttpRequest.send", KGENOME_NUCLEO_HTTP_SEND },
		{ "navigator.sendBeacon", KGENOME_NUCLEO_HTTP_SEND },
		{ "XMLHttpRequest.responseText", KGENOME_NUCLEO_HTTP_RECV },
		{ "dns.lookup", KGENOME_NUCLEO_DNS },
		{ "dns.resolve", KGENOME_NUCLEO_DNS },
		{ "dns.resolve4", KGENOME_NUCLEO_DNS },
		{ "dns.resolve6", KGENOME_NUCLEO_DNS },
		{ "dns.resolveTxt", KGENOME_NUCLEO_DNS },
		{ "dns.reverse", KGENOME_NUCLEO_DNS },
	};
	/* kept out on purpose; files of 3286 benign / 1356 malware that call it */
	static const struct nn_out out[] = {
		{ "String.fromCharCode", "130 / 1238" },
		{ "decodeURIComponent", "98 / 0" },
		{ "parseInt", "374 / 58" },
		{ "Buffer.from", "97 / 2" },
		{ "setTimeout", "330 / 80" },
		{ "setInterval", "109 / 1" },
		{ "document.write", "16 / 3" },
		{ "document.createElement", "181 / 16" },
		{ "require", "1608 / 4" },
		{ "exec", "149 / 0" },
		{ "spawn", "19 / 1" },
		{ "location.href", "180 / 60" },
		{ "URLSearchParams", "37 / 5" },
		{ "fs.existsSync", "26 / 1" },
		{ "process.platform", "88 / 1" },
		{ "window.moveTo", "0 / 1206" },
		{ "window.resizeTo", "2 / 1206" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"system",
		"fork",
		"chmod",
		"unlink",
		"socket",
		"CreateProcessA",
		"VirtualAlloc",
		"base64_decode",
		"shell_exec",
		"os.system",
		"subprocess.Popen",
		"WScript.Shell.Run",
		"Invoke-Expression",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"child_process.exec",
		"fs.readFileSync",
		"XMLHttpRequest.open",
		"vm.runInNewContext",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 8u },
		{ KGENOME_NUCLEO_CRYPTO, 5u },
		{ KGENOME_NUCLEO_EVAL, 6u },
		{ KGENOME_NUCLEO_CREATE, 3u },
		{ KGENOME_NUCLEO_DYNCALL, 2u },
		{ KGENOME_NUCLEO_DYNLOAD, 1u },
		{ KGENOME_NUCLEO_LIB_OPEN, 3u },
		{ KGENOME_NUCLEO_REQUEST, 13u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 7u },
		{ KGENOME_NUCLEO_FILE_OPEN, 3u },
		{ KGENOME_NUCLEO_WRITE, 7u },
		{ KGENOME_NUCLEO_FILE_DELETE, 6u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_PERM_SET, 4u },
		{ KGENOME_NUCLEO_TIMESTOMP, 2u },
		{ KGENOME_NUCLEO_NET_OPEN, 2u },
		{ KGENOME_NUCLEO_NET_CONNECT, 4u },
		{ KGENOME_NUCLEO_NET_LISTEN, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 5u },
		{ KGENOME_NUCLEO_HTTP_OPEN, 1u },
		{ KGENOME_NUCLEO_HTTP_CONNECT, 1u },
		{ KGENOME_NUCLEO_HTTP_SEND, 2u },
		{ KGENOME_NUCLEO_HTTP_RECV, 1u },
		{ KGENOME_NUCLEO_DNS, 6u },
	};
	unsigned rows, i;

	nn_check_is(TARGET, is, sizeof is / sizeof is[0]);
	nn_check_out(TARGET, out, sizeof out / sizeof out[0]);
	nn_check_absent(TARGET, absent, sizeof absent / sizeof absent[0]);
	for (i = 0; i < sizeof only / sizeof only[0]; i++) {
		NN_CK(kgenome_nucleo_cap_of_name(TARGET, only[i]) != KGENOME_NUCLEO_NONE);
		nn_check_only_here(TARGET, only[i]);
	}
	rows = nn_census(TARGET, cen, sizeof cen / sizeof cen[0]);
	NN_CK(rows == 95u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "child_process.execSync");
	nn_check_stable(TARGET, "child_process.execSync");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "child_process.execSync") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_js_names: the rows of the JavaScript table, in the case it keeps, and the names it keeps out");
}
