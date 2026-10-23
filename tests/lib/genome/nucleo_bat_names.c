/*
 * nucleo_bat_names - the commands of the batch table, and the ones it keeps out (libgenome/celllysis/nucleo_names_bat.c): every
 * row resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row
 * moved to another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and
 * the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every batch program there is. Each is pinned here with the
 * file count that decided it - in the 1122 benign / 45 malware files the table was measured on (the measurement and its limits
 * are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_BAT

int main(void)
{
	static const struct nn_is is[] = {
		{ "certutil", KGENOME_NUCLEO_DECODE },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "powershell", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "pwsh", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "cmd", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "wscript", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "cscript", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "mshta", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "rundll32", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "regsvr32", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "msiexec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "installutil", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "odbcconf", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "wmic", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "forfiles", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "runas", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "psexec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "wsl", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "bash", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "icacls", KGENOME_NUCLEO_PERM_SET },
		{ "cacls", KGENOME_NUCLEO_PERM_SET },
		{ "takeown", KGENOME_NUCLEO_PERM_SET },
		{ "curl", KGENOME_NUCLEO_HTTP_FETCH },
		{ "bitsadmin", KGENOME_NUCLEO_HTTP_FETCH },
		{ "ftp", KGENOME_NUCLEO_NET_CONNECT },
		{ "tftp", KGENOME_NUCLEO_NET_CONNECT },
		{ "telnet", KGENOME_NUCLEO_NET_CONNECT },
		{ "nc", KGENOME_NUCLEO_NET_CONNECT },
		{ "ncat", KGENOME_NUCLEO_NET_CONNECT },
		{ "nslookup", KGENOME_NUCLEO_DNS },
		{ "tasklist", KGENOME_NUCLEO_PROC_LIST },
	};
	/* kept out on purpose; files of 1122 benign / 45 malware that call it */
	static const struct nn_out out[] = {
		{ "del", "316 / 3" },
		{ "erase", "4 / 0" },
		{ "rmdir", "11 / 1" },
		{ "rd", "32 / 1" },
		{ "ren", "333 / 0" },
		{ "rename", "5 / 0" },
		{ "move", "11 / 1" },
		{ "copy", "151 / 2" },
		{ "xcopy", "91 / 0" },
		{ "mkdir", "30 / 5" },
		{ "md", "87 / 0" },
		{ "type", "12 / 0" },
		{ "attrib", "49 / 0" },
		{ "start", "27 / 6" },
		{ "call", "173 / 8" },
		{ "echo", "354 / 30" },
		{ "set", "259 / 23" },
		{ "goto", "130 / 13" },
		{ "ping", "2 / 1" },
		{ "timeout", "1 / 8" },
		{ "net", "6 / 2" },
		{ "sc", "2 / 1" },
		{ "reg", "1 / 3" },
		{ "schtasks", "0 / 2" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"system",
		"fork",
		"chmod",
		"unlink",
		"popen",
		"socket",
		"execve",
		"mmap",
		"base64_decode",
		"CreateProcessA",
		"VirtualAlloc",
		"shell_exec",
		"Invoke-Expression",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"icacls",
		"takeown",
		"tasklist",
		"certutil",
		"bitsadmin",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 1u },
		{ KGENOME_NUCLEO_DYNCALL, 1u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 17u },
		{ KGENOME_NUCLEO_PERM_SET, 3u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 2u },
		{ KGENOME_NUCLEO_NET_CONNECT, 5u },
		{ KGENOME_NUCLEO_DNS, 1u },
		{ KGENOME_NUCLEO_PROC_LIST, 1u },
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
	NN_CK(rows == 31u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 1, "certutil");
	nn_check_stable(TARGET, "certutil");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "certutil") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_bat_names: the rows of the batch table, in the case it keeps, and the names it keeps out");
}
