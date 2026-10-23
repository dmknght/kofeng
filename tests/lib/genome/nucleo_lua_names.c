/*
 * nucleo_lua_names - the rows of the Lua table, and the names it keeps out (libgenome/celllysis/nucleo_names_lua.c): every row
 * resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row moved to
 * another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and the names
 * of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every Lua program there is. Each is pinned here with the file
 * count that decided it - in the 346 benign / 609 nmap scripts files the table was measured on (the measurement and its limits
 * are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_LUA

int main(void)
{
	static const struct nn_is is[] = {
		{ "mime.unb64", KGENOME_NUCLEO_DECODE },
		{ "base64.decode", KGENOME_NUCLEO_DECODE },
		{ "base64.dec", KGENOME_NUCLEO_DECODE },
		{ "zlib.inflate", KGENOME_NUCLEO_DECODE },
		{ "zlib.decompress", KGENOME_NUCLEO_DECODE },
		{ "url.unescape", KGENOME_NUCLEO_DECODE },
		{ "loadstring", KGENOME_NUCLEO_CREATE },
		{ "load", KGENOME_NUCLEO_CREATE },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "dofile", KGENOME_NUCLEO_LIB_OPEN },
		{ "loadfile", KGENOME_NUCLEO_LIB_OPEN },
		{ "package.loadlib", KGENOME_NUCLEO_LIB_OPEN },
		{ "ngx.req.get_uri_args", KGENOME_NUCLEO_REQUEST },
		{ "ngx.req.get_post_args", KGENOME_NUCLEO_REQUEST },
		{ "ngx.req.get_body_data", KGENOME_NUCLEO_REQUEST },
		{ "ngx.req.get_headers", KGENOME_NUCLEO_REQUEST },
		{ "ngx.var", KGENOME_NUCLEO_REQUEST },
		{ "luci.http.formvalue", KGENOME_NUCLEO_REQUEST },
		{ "luci.http.content", KGENOME_NUCLEO_REQUEST },
		{ "cgilua.QUERY", KGENOME_NUCLEO_REQUEST },
		{ "cgilua.POST", KGENOME_NUCLEO_REQUEST },
		{ "os.execute", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "io.popen", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "posix.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "posix.system", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "nixio.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "luci.sys.call", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "luci.sys.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "luci.util.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "posix.fork", KGENOME_NUCLEO_SPAWN },
		{ "nixio.fork", KGENOME_NUCLEO_SPAWN },
		{ "os.remove", KGENOME_NUCLEO_FILE_DELETE },
		{ "posix.unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "nixio.fs.unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "os.rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "nixio.fs.rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "posix.chmod", KGENOME_NUCLEO_PERM_SET },
		{ "nixio.fs.chmod", KGENOME_NUCLEO_PERM_SET },
		{ "nixio.fs.writefile", KGENOME_NUCLEO_WRITE },
		{ "nixio.fs.copy", KGENOME_NUCLEO_WRITE },
		{ "lfs.touch", KGENOME_NUCLEO_TIMESTOMP },
		{ "socket.tcp", KGENOME_NUCLEO_NET_OPEN },
		{ "socket.udp", KGENOME_NUCLEO_NET_OPEN },
		{ "socket.connect", KGENOME_NUCLEO_NET_CONNECT },
		{ "socket.bind", KGENOME_NUCLEO_NET_BIND },
		{ "socket.http.request", KGENOME_NUCLEO_HTTP_FETCH },
		{ "http.request", KGENOME_NUCLEO_HTTP_FETCH },
		{ "https.request", KGENOME_NUCLEO_HTTP_FETCH },
		{ "socket.dns.toip", KGENOME_NUCLEO_DNS },
		{ "socket.dns.tohostname", KGENOME_NUCLEO_DNS },
	};
	/* kept out on purpose; files of 346 benign / 609 nmap scripts that call it */
	static const struct nn_out out[] = {
		{ "require", "238 / 608" },
		{ "io.open", "22 / 52" },
		{ "os.getenv", "10 / 0" },
		{ "os.time", "19 / 35" },
		{ "setmetatable", "129 / 105" },
		{ "pcall", "64 / 12" },
		{ "string.char", "35 / 24" },
		{ "unpack", "35 / 6" },
		{ "nmap.new_socket", "62 / 140" },
		{ "stdnse.sleep", "5 / 35" },
		{ "stdnse.fromhex", "16 / 33" },
		{ "http.get", "5 / 113" },
		{ "dns.query", "4 / 16" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"os.system",
		"subprocess.Popen",
		"shell_exec",
		"base64_decode",
		"VirtualAlloc",
		"child_process.exec",
		"Runtime.exec",
		"system",
		"popen",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"io.popen",
		"os.execute",
		"socket.tcp",
		"ngx.var",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 6u },
		{ KGENOME_NUCLEO_CREATE, 2u },
		{ KGENOME_NUCLEO_DYNCALL, 1u },
		{ KGENOME_NUCLEO_DYNLOAD, 1u },
		{ KGENOME_NUCLEO_LIB_OPEN, 3u },
		{ KGENOME_NUCLEO_REQUEST, 9u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 8u },
		{ KGENOME_NUCLEO_SPAWN, 2u },
		{ KGENOME_NUCLEO_FILE_DELETE, 3u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_PERM_SET, 2u },
		{ KGENOME_NUCLEO_WRITE, 2u },
		{ KGENOME_NUCLEO_TIMESTOMP, 1u },
		{ KGENOME_NUCLEO_NET_OPEN, 2u },
		{ KGENOME_NUCLEO_NET_CONNECT, 1u },
		{ KGENOME_NUCLEO_NET_BIND, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 3u },
		{ KGENOME_NUCLEO_DNS, 2u },
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
	NN_CK(rows == 51u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "socket.http.request");
	nn_check_stable(TARGET, "socket.http.request");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "socket.http.request") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_lua_names: the rows of the Lua table, in the case it keeps, and the names it keeps out");
}
