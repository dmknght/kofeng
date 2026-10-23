/*
 * nucleo_names_lua.c - what a Lua name means, in the vocabulary a native program's imports are read in.
 *
 * Lua's standard functions are written as the program writes them ("os.execute", "io.popen", "loadstring", "os.remove"), and
 * so are the functions of the libraries a Lua program is usually run with: LuaSocket ("socket.tcp", "socket.http.request"),
 * OpenResty ("ngx.req.get_uri_args"), the posix and lfs modules, and OpenWrt's nixio and luci, which are where the Lua of
 * routers and IoT devices (the Lua a bot or a backdoor is written in) lives. Case matters (no `fold`).
 *
 * THE EVIDENCE IS THE THINNEST OF ANY TABLE and the table says so: no Lua malware source exists on this machine (the two
 * Bazaar entries named Lua are zip archives of a LuaJIT loader and its executable, with no Lua text). What there is: 609
 * Nmap scripts (the Lua of an offensive tool, counted below as "nmap scripts"; they run in a sandbox that withholds
 * os.execute and io.popen, and they use Nmap's own libraries for the network) against 346 benign files (nselib, Neovim's
 * runtime and LuaJIT's own modules). So a name here is a row because it is the library's API for the act and does not occur
 * in the benign set at a rate that would make it noise, not because a sample used it. Every row is [Unverified] against
 * malware.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: LuaSocket's mime.unb64 is the base64 decoder most Lua programs use (0/346 benign, 0/609 nmap scripts);
	 * base64.decode is the one of the single-file libraries (2/346 benign, 0/609 nmap scripts); base64.dec is Nmap's own (5/346
	 * benign, 8/609 nmap scripts). The zlib bindings are the decompressors; url.unescape is the percent decoding.
	 */
	{ .name = "mime.unb64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.dec", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.inflate", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.decompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "url.unescape", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * CREATE: text that becomes a function: loadstring (2/346 benign, 0/609 nmap scripts) and load (8/346 benign, 2/609 nmap
	 * scripts; with a function argument it reads pieces, and with a string it is eval's first half: `loadstring(s)()` is the Lua
	 * eval, so the pair is create-then-call and not data-eval). DYNCALL: the row "(dynamic)" is `_G[name](...)`, `t[name](...)`
	 * and a call of a variable the program did not write as a name. DYNLOAD: the row "(load)" is `require(x)` with x not a
	 * literal. require with a literal is in 238/346 benign, 608/609 nmap scripts and is not a row.
	 */
	{ .name = "loadstring", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "load", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: code and libraries opened from a place: dofile and loadfile run or compile a file (6/346 benign, 7/609 nmap
	 * scripts), package.loadlib opens a native library.
	 */
	{ .name = "dofile", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "loadfile", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "package.loadlib", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender of an HTTP request chose, in the Lua of the web servers that embed it: OpenResty's ngx.req and
	 * ngx.var, LuCI's http.formvalue, CGILua's QUERY and POST.
	 */
	{ .name = "ngx.req.get_uri_args", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ngx.req.get_post_args", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ngx.req.get_body_data", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ngx.req.get_headers", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ngx.var", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "luci.http.formvalue", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "luci.http.content", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "cgilua.QUERY", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "cgilua.POST", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. os.execute and io.popen are the standard library's two ways,
	 * and the only reason a Lua backdoor is short; the others are the posix module's and OpenWrt's (luci.sys.call and exec).
	 * posix.fork and nixio.fork make a separate address space.
	 */
	{ .name = "os.execute", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "io.popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "posix.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "posix.system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "nixio.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "luci.sys.call", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "luci.sys.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "luci.util.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "posix.fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "nixio.fork", .cap = KGENOME_NUCLEO_SPAWN },
	/*
	 * FILE: os.remove and os.rename are the standard library's; the posix and nixio.fs modules are the rest. io.open is in
	 * 22/346 benign, 52/609 nmap scripts and is not a row.
	 */
	{ .name = "os.remove", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "posix.unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "nixio.fs.unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "os.rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "nixio.fs.rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "posix.chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "nixio.fs.chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "nixio.fs.writefile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "nixio.fs.copy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "lfs.touch", .cap = KGENOME_NUCLEO_TIMESTOMP },
	/*
	 * NETWORK: LuaSocket (socket.tcp and socket.udp make the socket, socket.connect and socket.bind do the rest in one call,
	 * socket.http.request fetches a URL) and the dns lookups it has. [Unverified: Nmap scripts reach the network through
	 * nmap.new_socket and nmap's own http library, which are the host program's API, not Lua's: they are left out below.]
	 */
	{ .name = "socket.tcp", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "socket.udp", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "socket.connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "socket.bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "socket.http.request", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "http.request", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "https.request", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "socket.dns.toip", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "socket.dns.tohostname", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 609 nmap scripts / 346 benign files: require
	 * 238/346 benign, 608/609 nmap scripts (every Lua file), io.open 22/346 benign, 52/609 nmap scripts, io.lines, io.output,
	 * os.getenv 10/346 benign, 0/609 nmap scripts, os.time 19/346 benign, 35/609 nmap scripts, os.date, os.clock, setmetatable
	 * 129/346 benign, 105/609 nmap scripts, pcall 64/346 benign, 12/609 nmap scripts, rawget, string.char 35/346 benign, 24/609
	 * nmap scripts, string.reverse, unpack 35/346 benign, 6/609 nmap scripts (what Lua uses for every binary record and every
	 * argument list), coroutine.wrap and coroutine.create (control flow); os.exit; the names of the host program -
	 * nmap.new_socket 62/346 benign, 140/609 nmap scripts, nmap.address_family, stdnse.sleep 5/346 benign, 35/609 nmap scripts,
	 * stdnse.fromhex 16/346 benign, 33/609 nmap scripts, http.get 5/346 benign, 113/609 nmap scripts, dns.query 4/346 benign,
	 * 16/609 nmap scripts - which are Nmap's API and say what Nmap is doing and not what Lua is, so a Lua table does not carry
	 * them. NOT NAMED because the vocabulary has no word: nothing in this language.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_lua = {
	.target = KGENOME_NUCLEO_T_LUA, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
