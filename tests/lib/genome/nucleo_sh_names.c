/*
 * nucleo_sh_names - the commands of the shell table, and the ones it keeps out (libgenome/celllysis/nucleo_names_sh.c): every
 * row resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row
 * moved to another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and
 * the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every POSIX shell program there is. Each is pinned here with
 * the file count that decided it - in the 2013 benign / 866 malware files the table was measured on (the measurement and its
 * limits are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_SH

int main(void)
{
	static const struct nn_is is[] = {
		{ "base64", KGENOME_NUCLEO_DECODE },
		{ "xxd", KGENOME_NUCLEO_DECODE },
		{ "gunzip", KGENOME_NUCLEO_DECODE },
		{ "uudecode", KGENOME_NUCLEO_DECODE },
		{ "rev", KGENOME_NUCLEO_DECODE },
		{ "openssl", KGENOME_NUCLEO_CRYPTO },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "source", KGENOME_NUCLEO_LIB_OPEN },
		{ "bash", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "sh", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "busybox", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "python", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "python3", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "perl", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "php", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "ruby", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "node", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "nohup", KGENOME_NUCLEO_BACKGROUND },
		{ "setsid", KGENOME_NUCLEO_BACKGROUND },
		{ "disown", KGENOME_NUCLEO_BACKGROUND },
		{ "mkfifo", KGENOME_NUCLEO_PIPE },
		{ "chmod", KGENOME_NUCLEO_PERM_SET },
		{ "chown", KGENOME_NUCLEO_PERM_SET },
		{ "chgrp", KGENOME_NUCLEO_PERM_SET },
		{ "shred", KGENOME_NUCLEO_FILE_DELETE },
		{ "unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "curl", KGENOME_NUCLEO_HTTP_FETCH },
		{ "wget", KGENOME_NUCLEO_HTTP_FETCH },
		{ "nc", KGENOME_NUCLEO_NET_CONNECT },
		{ "ncat", KGENOME_NUCLEO_NET_CONNECT },
		{ "netcat", KGENOME_NUCLEO_NET_CONNECT },
		{ "socat", KGENOME_NUCLEO_NET_CONNECT },
		{ "telnet", KGENOME_NUCLEO_NET_CONNECT },
		{ "ssh", KGENOME_NUCLEO_NET_CONNECT },
		{ "scp", KGENOME_NUCLEO_NET_CONNECT },
		{ "sftp", KGENOME_NUCLEO_NET_CONNECT },
		{ "ftp", KGENOME_NUCLEO_NET_CONNECT },
		{ "tftp", KGENOME_NUCLEO_NET_CONNECT },
		{ "/dev/tcp", KGENOME_NUCLEO_NET_CONNECT },
		{ "/dev/udp", KGENOME_NUCLEO_NET_CONNECT },
		{ "zmap", KGENOME_NUCLEO_NET_CONNECT },
		{ "nslookup", KGENOME_NUCLEO_DNS },
		{ "dig", KGENOME_NUCLEO_DNS },
		{ "QUERY_STRING", KGENOME_NUCLEO_REQUEST },
		{ "HTTP_COOKIE", KGENOME_NUCLEO_REQUEST },
		{ "HTTP_USER_AGENT", KGENOME_NUCLEO_REQUEST },
	};
	/* kept out on purpose; files of 2013 benign / 866 malware that call it */
	static const struct nn_out out[] = {
		{ "eval", "222 / 19" },
		{ "exec", "155 / 33" },
		{ "awk", "175 / 33" },
		{ "sleep", "280 / 69" },
		{ "echo", "1301 / 273" },
		{ "rm", "512 / 592" },
		{ "mv", "118 / 58" },
		{ "cp", "153 / 85" },
		{ "mkdir", "236 / 121" },
		{ "touch", "119 / 29" },
		{ "cat", "330 / 162" },
		{ "tee", "13 / 4" },
		{ "tar", "44 / 9" },
		{ "tr", "85 / 32" },
		{ "sudo", "45 / 5" },
		{ "su", "2 / 3" },
		{ "kill", "96 / 93" },
		{ "pkill", "0 / 20" },
		{ "uname", "36 / 74" },
		{ "host", "2 / 0" },
		{ "getent", "3 / 0" },
		{ "ping", "19 / 0" },
		{ ".", "529 / 19" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"os.system",
		"shell_exec",
		"base64_decode",
		"CreateProcessA",
		"VirtualAlloc",
		"WScript.Shell.Run",
		"Invoke-Expression",
		"mmap",
		"_GET",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"nohup",
		"disown",
		"busybox",
		"/dev/tcp",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 5u },
		{ KGENOME_NUCLEO_CRYPTO, 1u },
		{ KGENOME_NUCLEO_DYNCALL, 1u },
		{ KGENOME_NUCLEO_LIB_OPEN, 1u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 9u },
		{ KGENOME_NUCLEO_BACKGROUND, 3u },
		{ KGENOME_NUCLEO_PIPE, 1u },
		{ KGENOME_NUCLEO_PERM_SET, 3u },
		{ KGENOME_NUCLEO_FILE_DELETE, 2u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 2u },
		{ KGENOME_NUCLEO_NET_CONNECT, 13u },
		{ KGENOME_NUCLEO_DNS, 2u },
		{ KGENOME_NUCLEO_REQUEST, 3u },
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
	NN_CK(rows == 46u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "base64");
	nn_check_stable(TARGET, "base64");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "base64") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_sh_names: the rows of the POSIX shell table, in the case it keeps, and the names it keeps out");
}
