/*
 * nucleo_perl_names - the rows of the Perl table, and the names it keeps out (libgenome/celllysis/nucleo_names_perl.c): every
 * row resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row
 * moved to another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and
 * the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every Perl program there is. Each is pinned here with the file
 * count that decided it - in the 2624 benign / 31 malware files the table was measured on (the measurement and its limits are
 * in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_PERL

int main(void)
{
	static const struct nn_is is[] = {
		{ "decode_base64", KGENOME_NUCLEO_DECODE },
		{ "MIME.Base64.decode_base64", KGENOME_NUCLEO_DECODE },
		{ "uri_unescape", KGENOME_NUCLEO_DECODE },
		{ "URI.Escape.uri_unescape", KGENOME_NUCLEO_DECODE },
		{ "uncompress", KGENOME_NUCLEO_DECODE },
		{ "Compress.Zlib.uncompress", KGENOME_NUCLEO_DECODE },
		{ "memGunzip", KGENOME_NUCLEO_DECODE },
		{ "Compress.Zlib.memGunzip", KGENOME_NUCLEO_DECODE },
		{ "eval", KGENOME_NUCLEO_EVAL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "ENV.QUERY_STRING", KGENOME_NUCLEO_REQUEST },
		{ "ENV.HTTP_COOKIE", KGENOME_NUCLEO_REQUEST },
		{ "ENV.HTTP_USER_AGENT", KGENOME_NUCLEO_REQUEST },
		{ "ENV.CONTENT_LENGTH", KGENOME_NUCLEO_REQUEST },
		{ "CGI.param", KGENOME_NUCLEO_REQUEST },
		{ "system", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "readpipe", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "open3", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "open2", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "IPC.Open3.open3", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "IPC.Open2.open2", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "fork", KGENOME_NUCLEO_SPAWN },
		{ "POSIX.setsid", KGENOME_NUCLEO_BACKGROUND },
		{ "POSIX.dup2", KGENOME_NUCLEO_FD_REDIR },
		{ "unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "move", KGENOME_NUCLEO_FILE_RENAME },
		{ "chmod", KGENOME_NUCLEO_PERM_SET },
		{ "chown", KGENOME_NUCLEO_PERM_SET },
		{ "utime", KGENOME_NUCLEO_TIMESTOMP },
		{ "copy", KGENOME_NUCLEO_WRITE },
		{ "socket", KGENOME_NUCLEO_NET_OPEN },
		{ "connect", KGENOME_NUCLEO_NET_CONNECT },
		{ "IO.Socket.INET.new", KGENOME_NUCLEO_NET_CONNECT },
		{ "Net.FTP.new", KGENOME_NUCLEO_NET_CONNECT },
		{ "Net.Telnet.new", KGENOME_NUCLEO_NET_CONNECT },
		{ "bind", KGENOME_NUCLEO_NET_BIND },
		{ "listen", KGENOME_NUCLEO_NET_LISTEN },
		{ "accept", KGENOME_NUCLEO_NET_ACCEPT },
		{ "recv", KGENOME_NUCLEO_NET_READ },
		{ "send", KGENOME_NUCLEO_NET_WRITE },
		{ "inet_aton", KGENOME_NUCLEO_NET_ADDR },
		{ "inet_ntoa", KGENOME_NUCLEO_NET_ADDR },
		{ "sockaddr_in", KGENOME_NUCLEO_NET_ADDR },
		{ "pack_sockaddr_in", KGENOME_NUCLEO_NET_ADDR },
		{ "LWP.UserAgent.new", KGENOME_NUCLEO_HTTP_OPEN },
		{ "HTTP.Tiny.new", KGENOME_NUCLEO_HTTP_OPEN },
		{ "LWP.Simple.get", KGENOME_NUCLEO_HTTP_FETCH },
		{ "LWP.Simple.getstore", KGENOME_NUCLEO_HTTP_FETCH },
		{ "getstore", KGENOME_NUCLEO_HTTP_FETCH },
		{ "gethostbyname", KGENOME_NUCLEO_DNS },
		{ "gethostbyaddr", KGENOME_NUCLEO_DNS },
		{ "Socket.getaddrinfo", KGENOME_NUCLEO_DNS },
		{ "Net.DNS.Resolver.new", KGENOME_NUCLEO_DNS },
	};
	/* kept out on purpose; files of 2624 benign / 31 malware that call it */
	static const struct nn_out out[] = {
		{ "open", "317 / 20" },
		{ "close", "314 / 19" },
		{ "print", "530 / 28" },
		{ "opendir", "40 / 1" },
		{ "mkdir", "47 / 0" },
		{ "glob", "34 / 0" },
		{ "stat", "68 / 5" },
		{ "pack", "79 / 8" },
		{ "unpack", "220 / 5" },
		{ "reverse", "58 / 0" },
		{ "chr", "50 / 2" },
		{ "ord", "60 / 1" },
		{ "sleep", "71 / 14" },
		{ "alarm", "8 / 5" },
		{ "srand", "37 / 2" },
		{ "exit", "134 / 20" },
		{ "require", "791 / 9" },
		{ "use", "1412 / 24" },
		{ "do", "158 / 6" },
		{ "ref", "403 / 1" },
		{ "can", "22 / 0" },
		{ "kill", "15 / 1" },
		{ "waitpid", "14 / 11" },
		{ "shutdown", "4 / 7" },
		{ "crypt", "2 / 1" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"os.system",
		"subprocess.Popen",
		"shell_exec",
		"base64_decode",
		"CreateProcessA",
		"VirtualAlloc",
		"child_process.exec",
		"StrReverse",
		"Runtime.exec",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"decode_base64",
		"MIME.Base64.decode_base64",
		"IO.Socket.INET.new",
		"LWP.UserAgent.new",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 8u },
		{ KGENOME_NUCLEO_EVAL, 1u },
		{ KGENOME_NUCLEO_DYNCALL, 1u },
		{ KGENOME_NUCLEO_DYNLOAD, 1u },
		{ KGENOME_NUCLEO_REQUEST, 5u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 7u },
		{ KGENOME_NUCLEO_SPAWN, 1u },
		{ KGENOME_NUCLEO_BACKGROUND, 1u },
		{ KGENOME_NUCLEO_FD_REDIR, 1u },
		{ KGENOME_NUCLEO_FILE_DELETE, 1u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_PERM_SET, 2u },
		{ KGENOME_NUCLEO_TIMESTOMP, 1u },
		{ KGENOME_NUCLEO_WRITE, 1u },
		{ KGENOME_NUCLEO_NET_OPEN, 1u },
		{ KGENOME_NUCLEO_NET_CONNECT, 4u },
		{ KGENOME_NUCLEO_NET_BIND, 1u },
		{ KGENOME_NUCLEO_NET_LISTEN, 1u },
		{ KGENOME_NUCLEO_NET_ACCEPT, 1u },
		{ KGENOME_NUCLEO_NET_READ, 1u },
		{ KGENOME_NUCLEO_NET_WRITE, 1u },
		{ KGENOME_NUCLEO_NET_ADDR, 4u },
		{ KGENOME_NUCLEO_HTTP_OPEN, 2u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 3u },
		{ KGENOME_NUCLEO_DNS, 4u },
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
	NN_CK(rows == 56u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "MIME.Base64.decode_base64");
	nn_check_stable(TARGET, "MIME.Base64.decode_base64");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "MIME.Base64.decode_base64") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_perl_names: the rows of the Perl table, in the case it keeps, and the names it keeps out");
}
