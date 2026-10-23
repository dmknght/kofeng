/*
 * nucleo_names_js.c - what a JavaScript name means: node, the browser and the JScript of the Windows Script Host, which are
 * one lexer and one syntax with APIs that do not collide (child_process.exec, document.cookie, `new ActiveXObject`), so one
 * table answers all three.
 *
 * Names are spelled as the program writes them and case matters (no `fold`). A node module function is written with its
 * module ("child_process.exec", "fs.readFileSync"): the bare name after a destructuring `const { exec } = require(...)` is
 * not a row, because `exec` alone is also RegExp.prototype.exec. A member of an object the program holds in a variable is
 * written with the CLASS of the object when it is not a module ("XMLHttpRequest.open"). THE COM OBJECTS A JSCRIPT CREATES
 * ARE NOT HERE: `new ActiveXObject("WScript.Shell").Run(...)` is the same object as VBScript's and is the row
 * "WScript.Shell.Run" of the VBS table, which is where the Windows Script Host and COM are written once.
 *
 * The evidence is 1356 malware files (WSH droppers and HTA downloaders; they cluster into 275 families by the tokens they
 * share, and one family of HTA files - the ones that move their window off screen - is nine in ten of them), against 3286
 * benign files of this machine (editor extensions, web pages, node tools). [Unverified: the malware here is Windows script
 * malware; nothing of it is node, so the node rows rest on the benign counts and the documented API, and say so.]
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: atob is base64 (42/3286 benign, 0/1356 malware; as a member of window 5/3286 benign, 0/1356 malware), unescape is
	 * the percent decoding that obfuscated scripts use on a whole payload (52/3286 benign, 7/1356 malware). The node zlib calls
	 * are the stream side of the same step. [Unverified: none of the zlib rows occurs in a malware file here.]
	 */
	{ .name = "atob", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "window.atob", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "unescape", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.inflateSync", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.gunzipSync", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.unzipSync", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.inflateRawSync", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "pako.inflate", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * With a key: the same step, and the weaker word is what a rule about "a decode" must not miss. [Unverified: documented node
	 * and CryptoJS API; no sample here.]
	 */
	{ .name = "crypto.createDecipheriv", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "crypto.createDecipher", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "crypto.createCipheriv", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptoJS.AES.decrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptoJS.AES.encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * EVAL: text run as code, now. eval is 78/3286 benign, 15/1356 malware: not rarer in the malware than in the benign files,
	 * which is the honest reason the join (a decode that reaches it) and not the name is the evidence; it stays a row because it
	 * is the word the decoders feed. The vm functions are node's way to run a string; execScript is the old browser form. A
	 * string passed to setTimeout or setInterval is run the same way, but the first argument is an ordinary callback in almost
	 * every call (setTimeout 330/3286 benign, 80/1356 malware, setInterval 109/3286 benign, 1/1356 malware), so those names are
	 * not rows: the argument is the matcher's.
	 * CREATE: text that becomes a function. `new Function(text)` is spelled "Function" (a call of it, with or without `new`);
	 * the benign count of the bare name is inflated by `instanceof Function` and `typeof`, which are not calls (126/3286 benign,
	 * 1/1356 malware).
	 */
	{ .name = "eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "window.eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "execScript", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "vm.runInNewContext", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "vm.runInThisContext", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "vm.runInContext", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "Function", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "vm.Script", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "vm.compileFunction", .cap = KGENOME_NUCLEO_CREATE },
	/*
	 * DYNCALL: a callee that is a value. The row "(dynamic)" is `window[name](...)`, `obj[name](...)`, `this[name]()` and a call
	 * of a variable holding anything the program did not write as a name; Reflect.apply is the explicit form (23/3286 benign,
	 * 0/1356 malware). DYNLOAD: the row "(load)" is `require(x)` and `import(x)` with x not a literal, and `new
	 * ActiveXObject(x)`: a module or class named by a value. A literal `require("fs")` is in about half of the benign files
	 * (1608/3286 benign, 4/1356 malware) and is not a row.
	 */
	{ .name = "Reflect.apply", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: code loaded from a place: a worker's importScripts, node's process.dlopen, and the ffi binding of native
	 * libraries. [Unverified: no sample.]
	 */
	{ .name = "importScripts", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "process.dlopen", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "ffi.Library", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender chose. Express and its kin keep it in the members of the request object, spelled as written
	 * (`req`, the name every handler gives it, and `request`); the browser keeps what the sender of the LINK chose in location,
	 * document.cookie and window.name (the sender of a link is the one who chooses what a DOM-XSS runs). req.query 1/3286
	 * benign, 0/1356 malware, req.body 1/3286 benign, 0/1356 malware, location.hash 42/3286 benign, 0/1356 malware,
	 * location.search 33/3286 benign, 0/1356 malware, document.cookie 41/3286 benign, 14/1356 malware. [Unverified: neither the
	 * malware nor the benign set here is a web application, so these are the API and not a measurement.]
	 */
	{ .name = "req.query", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "req.body", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "req.params", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "req.cookies", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "req.files", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.query", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.body", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.params", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.payload", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "location.hash", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "location.search", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "document.cookie", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "window.name", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: node's child_process, the native word being proc-start for every one of them. child_process.exec 2/3286 benign,
	 * 0/1356 malware, spawn 2/3286 benign, 0/1356 malware. [Unverified: none in a malware file here.]
	 */
	{ .name = "child_process.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "child_process.execSync", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "child_process.spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "child_process.spawnSync", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "child_process.execFile", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "child_process.execFileSync", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "child_process.fork", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * FILE: node's fs, with the words the PHP table uses for the same acts - the open and read is file-open, the whole-file and
	 * appending writes and the copy are file-write, and unlink, rename, chmod and utimes are the file-delete, file-rename,
	 * perm-set and timestomp. [Unverified: fs.readFileSync is 44/3286 benign, 0/1356 malware, fs.writeFileSync 14/3286 benign,
	 * 1/1356 malware, fs.unlinkSync 8/3286 benign, 1/1356 malware; none of the malware here is node, so these are counts of
	 * tools and editors.]
	 */
	{ .name = "fs.readFile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "fs.readFileSync", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "fs.createReadStream", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "fs.writeFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.writeFileSync", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.appendFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.appendFileSync", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.createWriteStream", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.copyFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.copyFileSync", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "fs.unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "fs.unlinkSync", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "fs.rm", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "fs.rmSync", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "fs.rmdir", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "fs.rmdirSync", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "fs.rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "fs.renameSync", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "fs.chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fs.chmodSync", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fs.chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fs.chownSync", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fs.utimes", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "fs.utimesSync", .cap = KGENOME_NUCLEO_TIMESTOMP },
	/*
	 * NETWORK: node's net, tls and dgram as sockets; the http modules, fetch, XMLHttpRequest and sendBeacon as the HTTP layer
	 * above, with the words the native table gives the Windows HTTP API (open, connect to a URL, send, receive; and a one-call
	 * fetch). XMLHttpRequest 49/3286 benign, 78/1356 malware and fetch 76/3286 benign, 1/1356 malware are in a few web pages;
	 * http.request 3/3286 benign, 1/1356 malware. A WebSocket is a connection.
	 */
	{ .name = "net.Socket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "dgram.createSocket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "net.connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "net.createConnection", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "tls.connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "WebSocket", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "net.createServer", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "http.request", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "http.get", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "https.request", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "https.get", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "fetch", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "XMLHttpRequest", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "XMLHttpRequest.open", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "XMLHttpRequest.send", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "navigator.sendBeacon", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "XMLHttpRequest.responseText", .cap = KGENOME_NUCLEO_HTTP_RECV },
	/*
	 * Every lookup node's dns module has is the same act as gethostbyname. [Unverified: no sample.]
	 */
	{ .name = "dns.lookup", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns.resolve", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns.resolve4", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns.resolve6", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns.resolveTxt", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dns.reverse", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 1356 malware / 3286 benign files:
	 * String.fromCharCode 130/3286 benign, 1238/1356 malware (the obfuscation primitive of the largest family of the corpus and
	 * also what every program that builds a character calls: a row would put a node in both; a diagnose joins it to the eval it
	 * feeds), decodeURIComponent 98/3286 benign, 0/1356 malware, decodeURI, parseInt 374/3286 benign, 58/1356 malware,
	 * Buffer.from 97/3286 benign, 2/1356 malware; setTimeout 330/3286 benign, 80/1356 malware, setInterval 109/3286 benign,
	 * 1/1356 malware, document.write 16/3286 benign, 3/1356 malware, document.createElement 181/3286 benign, 16/1356 malware
	 * (script injection is an argument); require with a literal 1608/3286 benign, 4/1356 malware; exec 149/3286 benign, 0/1356
	 * malware, spawn 19/3286 benign, 1/1356 malware and the other bare names a module member can be destructured to (the module
	 * is the identity); Function.prototype.call and apply, process.binding, import; location.href 180/3286 benign, 60/1356
	 * malware, document.referrer, navigator.userAgent, URLSearchParams 37/3286 benign, 5/1356 malware; fs.readdir, fs.existsSync
	 * 26/3286 benign, 1/1356 malware, fs.mkdir and the rest of fs that probes or lists; process.env, process.exit,
	 * process.platform 88/3286 benign, 1/1356 malware; localStorage; the Windows Script Host's COM objects, which are the VBS
	 * table's, and its WScript.Sleep and WScript.Quit, which that table keeps out too. NOT NAMED because the vocabulary has no
	 * word: hiding the window of an HTA or WSH script (window.moveTo 0/3286 benign, 1206/1356 malware, window.resizeTo 2/3286
	 * benign, 1206/1356 malware, ShowWindow = 0).
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_js = {
	.target = KGENOME_NUCLEO_T_JS, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
