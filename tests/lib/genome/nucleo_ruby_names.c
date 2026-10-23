/*
 * nucleo_ruby_names - the rows of the Ruby table, and the names it keeps out (libgenome/celllysis/nucleo_names_ruby.c): every
 * row resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row
 * moved to another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and
 * the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every Ruby program there is. Each is pinned here with the file
 * count that decided it - in the 338 benign / 5211 Metasploit files the table was measured on (the measurement and its limits
 * are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_RUBY

int main(void)
{
	static const struct nn_is is[] = {
		{ "Base64.decode64", KGENOME_NUCLEO_DECODE },
		{ "Base64.strict_decode64", KGENOME_NUCLEO_DECODE },
		{ "Base64.urlsafe_decode64", KGENOME_NUCLEO_DECODE },
		{ "Zlib.inflate", KGENOME_NUCLEO_DECODE },
		{ "Zlib.Inflate.inflate", KGENOME_NUCLEO_DECODE },
		{ "Zlib.gunzip", KGENOME_NUCLEO_DECODE },
		{ "Zlib.GzipReader.new", KGENOME_NUCLEO_DECODE },
		{ "CGI.unescape", KGENOME_NUCLEO_DECODE },
		{ "URI.decode_www_form_component", KGENOME_NUCLEO_DECODE },
		{ "URI.decode", KGENOME_NUCLEO_DECODE },
		{ "eval", KGENOME_NUCLEO_EVAL },
		{ "Kernel.eval", KGENOME_NUCLEO_EVAL },
		{ "instance_eval", KGENOME_NUCLEO_EVAL },
		{ "class_eval", KGENOME_NUCLEO_EVAL },
		{ "module_eval", KGENOME_NUCLEO_EVAL },
		{ "send", KGENOME_NUCLEO_DYNCALL },
		{ "public_send", KGENOME_NUCLEO_DYNCALL },
		{ "__send__", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "const_get", KGENOME_NUCLEO_DYNLOAD },
		{ "Object.const_get", KGENOME_NUCLEO_DYNLOAD },
		{ "Marshal.load", KGENOME_NUCLEO_DYNLOAD },
		{ "Marshal.restore", KGENOME_NUCLEO_DYNLOAD },
		{ "YAML.load", KGENOME_NUCLEO_DYNLOAD },
		{ "YAML.unsafe_load", KGENOME_NUCLEO_DYNLOAD },
		{ "Psych.load", KGENOME_NUCLEO_DYNLOAD },
		{ "Psych.unsafe_load", KGENOME_NUCLEO_DYNLOAD },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "load", KGENOME_NUCLEO_LIB_OPEN },
		{ "Fiddle.dlopen", KGENOME_NUCLEO_LIB_OPEN },
		{ "DL.dlopen", KGENOME_NUCLEO_LIB_OPEN },
		{ "params", KGENOME_NUCLEO_REQUEST },
		{ "request.params", KGENOME_NUCLEO_REQUEST },
		{ "request.body", KGENOME_NUCLEO_REQUEST },
		{ "request.cookies", KGENOME_NUCLEO_REQUEST },
		{ "CGI.new", KGENOME_NUCLEO_REQUEST },
		{ "system", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Kernel.system", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Kernel.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Kernel.spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Process.spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "IO.popen", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Open3.capture2", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Open3.capture2e", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Open3.capture3", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Open3.popen2", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Open3.popen3", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "PTY.spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "fork", KGENOME_NUCLEO_SPAWN },
		{ "Process.fork", KGENOME_NUCLEO_SPAWN },
		{ "Process.setsid", KGENOME_NUCLEO_BACKGROUND },
		{ "Process.daemon", KGENOME_NUCLEO_BACKGROUND },
		{ "File.delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "File.unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "FileUtils.rm", KGENOME_NUCLEO_FILE_DELETE },
		{ "FileUtils.rm_r", KGENOME_NUCLEO_FILE_DELETE },
		{ "FileUtils.rm_rf", KGENOME_NUCLEO_FILE_DELETE },
		{ "FileUtils.remove_entry", KGENOME_NUCLEO_FILE_DELETE },
		{ "File.rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "FileUtils.mv", KGENOME_NUCLEO_FILE_RENAME },
		{ "File.chmod", KGENOME_NUCLEO_PERM_SET },
		{ "FileUtils.chmod", KGENOME_NUCLEO_PERM_SET },
		{ "File.chown", KGENOME_NUCLEO_PERM_SET },
		{ "FileUtils.chown", KGENOME_NUCLEO_PERM_SET },
		{ "File.utime", KGENOME_NUCLEO_TIMESTOMP },
		{ "File.write", KGENOME_NUCLEO_WRITE },
		{ "File.binwrite", KGENOME_NUCLEO_WRITE },
		{ "FileUtils.cp", KGENOME_NUCLEO_WRITE },
		{ "UDPSocket.new", KGENOME_NUCLEO_NET_OPEN },
		{ "Socket.new", KGENOME_NUCLEO_NET_OPEN },
		{ "TCPSocket.new", KGENOME_NUCLEO_NET_CONNECT },
		{ "TCPSocket.open", KGENOME_NUCLEO_NET_CONNECT },
		{ "Socket.tcp", KGENOME_NUCLEO_NET_CONNECT },
		{ "Net.FTP.new", KGENOME_NUCLEO_NET_CONNECT },
		{ "Net.Telnet.new", KGENOME_NUCLEO_NET_CONNECT },
		{ "Net.SSH.start", KGENOME_NUCLEO_NET_CONNECT },
		{ "TCPServer.new", KGENOME_NUCLEO_NET_LISTEN },
		{ "Net.HTTP.new", KGENOME_NUCLEO_HTTP_OPEN },
		{ "Net.HTTP.start", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "Net.HTTP.get", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Net.HTTP.get_response", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Net.HTTP.post", KGENOME_NUCLEO_HTTP_FETCH },
		{ "URI.open", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Resolv.getaddress", KGENOME_NUCLEO_DNS },
		{ "Resolv.getaddresses", KGENOME_NUCLEO_DNS },
		{ "Resolv.getname", KGENOME_NUCLEO_DNS },
		{ "Socket.gethostbyname", KGENOME_NUCLEO_DNS },
		{ "IPSocket.getaddress", KGENOME_NUCLEO_DNS },
		{ "Resolv.DNS.new", KGENOME_NUCLEO_DNS },
	};
	/* kept out on purpose; files of 338 benign / 5211 Metasploit that call it */
	static const struct nn_out out[] = {
		{ "File.open", "28 / 244" },
		{ "File.read", "10 / 108" },
		{ "File.binread", "2 / 66" },
		{ "FileUtils.mkdir_p", "17 / 27" },
		{ "autoload", "17 / 0" },
		{ "require", "106 / 698" },
		{ "require_relative", "129 / 0" },
		{ "ENV", "33 / 33" },
		{ "ARGV", "7 / 34" },
		{ "sleep", "2 / 179" },
		{ "proc", "13 / 83" },
		{ "lambda", "9 / 57" },
		{ "Class.new", "4 / 1" },
		{ "method", "13 / 154" },
		{ "open", "3 / 11" },
		{ "ERB.new", "2 / 9" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"os.system",
		"subprocess.Popen",
		"shell_exec",
		"base64_decode",
		"decode_base64",
		"CreateProcessA",
		"VirtualAlloc",
		"child_process.exec",
		"Runtime.exec",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"Base64.decode64",
		"Open3.capture3",
		"Net.HTTP.get",
		"instance_eval",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 10u },
		{ KGENOME_NUCLEO_EVAL, 5u },
		{ KGENOME_NUCLEO_DYNCALL, 4u },
		{ KGENOME_NUCLEO_DYNLOAD, 9u },
		{ KGENOME_NUCLEO_LIB_OPEN, 3u },
		{ KGENOME_NUCLEO_REQUEST, 5u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 14u },
		{ KGENOME_NUCLEO_SPAWN, 2u },
		{ KGENOME_NUCLEO_BACKGROUND, 2u },
		{ KGENOME_NUCLEO_FILE_DELETE, 6u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_PERM_SET, 4u },
		{ KGENOME_NUCLEO_TIMESTOMP, 1u },
		{ KGENOME_NUCLEO_WRITE, 3u },
		{ KGENOME_NUCLEO_NET_OPEN, 2u },
		{ KGENOME_NUCLEO_NET_CONNECT, 6u },
		{ KGENOME_NUCLEO_NET_LISTEN, 1u },
		{ KGENOME_NUCLEO_HTTP_OPEN, 1u },
		{ KGENOME_NUCLEO_HTTP_CONNECT, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 4u },
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
	NN_CK(rows == 91u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "Net.HTTP.get");
	nn_check_stable(TARGET, "Net.HTTP.get");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "Net.HTTP.get") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_ruby_names: the rows of the Ruby table, in the case it keeps, and the names it keeps out");
}
