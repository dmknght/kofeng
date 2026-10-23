/*
 * nucleo_psh_names - the rows of the PowerShell table, and the names it keeps out (libgenome/celllysis/nucleo_names_psh.c):
 * every row resolves to its capability and gives its own name back through its id, the capability of every row is counted (a
 * row moved to another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing,
 * and the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every PowerShell program there is. Each is pinned here with
 * the file count that decided it - in the 59 benign / 78 malware files the table was measured on (the measurement and its
 * limits are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_PSH

int main(void)
{
	static const struct nn_is is[] = {
		{ "Convert.FromBase64String", KGENOME_NUCLEO_DECODE },
		{ "IO.Compression.GzipStream", KGENOME_NUCLEO_DECODE },
		{ "IO.Compression.DeflateStream", KGENOME_NUCLEO_DECODE },
		{ "Invoke-Expression", KGENOME_NUCLEO_EVAL },
		{ "iex", KGENOME_NUCLEO_EVAL },
		{ "InvokeCommand.InvokeScript", KGENOME_NUCLEO_EVAL },
		{ "ScriptBlock.Create", KGENOME_NUCLEO_CREATE },
		{ "Add-Type", KGENOME_NUCLEO_CREATE },
		{ "Invoke", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "Reflection.Assembly.Load", KGENOME_NUCLEO_DYNLOAD },
		{ "Reflection.Assembly.LoadFile", KGENOME_NUCLEO_DYNLOAD },
		{ "Reflection.Assembly.LoadFrom", KGENOME_NUCLEO_DYNLOAD },
		{ "Reflection.Assembly.LoadWithPartialName", KGENOME_NUCLEO_DYNLOAD },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "Start-Process", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Diagnostics.Process.Start", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "powershell", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "pwsh", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "cmd", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "wscript", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "cscript", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "mshta", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "rundll32", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "regsvr32", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "IO.File.ReadAllBytes", KGENOME_NUCLEO_FILE_OPEN },
		{ "IO.File.ReadAllText", KGENOME_NUCLEO_FILE_OPEN },
		{ "Set-Content", KGENOME_NUCLEO_WRITE },
		{ "Add-Content", KGENOME_NUCLEO_WRITE },
		{ "IO.File.WriteAllBytes", KGENOME_NUCLEO_WRITE },
		{ "IO.File.WriteAllText", KGENOME_NUCLEO_WRITE },
		{ "IO.File.AppendAllText", KGENOME_NUCLEO_WRITE },
		{ "IO.File.Delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "Move-Item", KGENOME_NUCLEO_FILE_RENAME },
		{ "Rename-Item", KGENOME_NUCLEO_FILE_RENAME },
		{ "Set-Acl", KGENOME_NUCLEO_PERM_SET },
		{ "Set-ItemProperty", KGENOME_NUCLEO_REG_SET },
		{ "New-ItemProperty", KGENOME_NUCLEO_REG_SET },
		{ "Remove-ItemProperty", KGENOME_NUCLEO_REG_SET },
		{ "New-Service", KGENOME_NUCLEO_SVC_INSTALL },
		{ "Invoke-WebRequest", KGENOME_NUCLEO_HTTP_FETCH },
		{ "iwr", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Invoke-RestMethod", KGENOME_NUCLEO_HTTP_FETCH },
		{ "irm", KGENOME_NUCLEO_HTTP_FETCH },
		{ "curl", KGENOME_NUCLEO_HTTP_FETCH },
		{ "wget", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Start-BitsTransfer", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Net.WebClient.DownloadString", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Net.WebClient.DownloadFile", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Net.WebClient.DownloadData", KGENOME_NUCLEO_HTTP_FETCH },
		{ "Net.WebClient", KGENOME_NUCLEO_HTTP_OPEN },
		{ "Net.WebClient.UploadString", KGENOME_NUCLEO_HTTP_SEND },
		{ "Net.WebClient.UploadFile", KGENOME_NUCLEO_HTTP_SEND },
		{ "Net.WebClient.UploadData", KGENOME_NUCLEO_HTTP_SEND },
		{ "Net.Sockets.TcpClient", KGENOME_NUCLEO_NET_CONNECT },
		{ "Net.Sockets.TcpListener", KGENOME_NUCLEO_NET_LISTEN },
		{ "Net.Sockets.UdpClient", KGENOME_NUCLEO_NET_OPEN },
		{ "Resolve-DnsName", KGENOME_NUCLEO_DNS },
		{ "Net.Dns.GetHostAddresses", KGENOME_NUCLEO_DNS },
		{ "Net.Dns.GetHostEntry", KGENOME_NUCLEO_DNS },
		{ "Net.Dns.GetHostByName", KGENOME_NUCLEO_DNS },
	};
	/* kept out on purpose; files of 59 benign / 78 malware that call it */
	static const struct nn_out out[] = {
		{ "Start-Sleep", "6 / 20" },
		{ "Get-Content", "9 / 2" },
		{ "Out-File", "1 / 1" },
		{ "Remove-Item", "13 / 10" },
		{ "Copy-Item", "8 / 9" },
		{ "New-Item", "8 / 16" },
		{ "Get-ChildItem", "5 / 4" },
		{ "Get-ItemProperty", "0 / 3" },
		{ "Get-Process", "2 / 5" },
		{ "Get-WmiObject", "1 / 3" },
		{ "Get-CimInstance", "3 / 2" },
		{ "Invoke-CimMethod", "0 / 0" },
		{ "New-Object", "19 / 45" },
		{ "Import-Module", "6 / 0" },
		{ "param", "32 / 37" },
		{ "Write-Host", "19 / 15" },
		{ "Stop-Process", "0 / 5" },
		{ "schtasks", "1 / 6" },
		{ "Invoke-Command", "0 / 0" },
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
		"ShellExecuteA",
		"shell_exec",
		"eval",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"Invoke-WebRequest",
		"Set-ItemProperty",
		"ScriptBlock.Create",
		"Net.WebClient.DownloadString",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 3u },
		{ KGENOME_NUCLEO_EVAL, 3u },
		{ KGENOME_NUCLEO_CREATE, 2u },
		{ KGENOME_NUCLEO_DYNCALL, 2u },
		{ KGENOME_NUCLEO_DYNLOAD, 5u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 10u },
		{ KGENOME_NUCLEO_FILE_OPEN, 2u },
		{ KGENOME_NUCLEO_WRITE, 5u },
		{ KGENOME_NUCLEO_FILE_DELETE, 1u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_PERM_SET, 1u },
		{ KGENOME_NUCLEO_REG_SET, 3u },
		{ KGENOME_NUCLEO_SVC_INSTALL, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 10u },
		{ KGENOME_NUCLEO_HTTP_OPEN, 1u },
		{ KGENOME_NUCLEO_HTTP_SEND, 3u },
		{ KGENOME_NUCLEO_NET_CONNECT, 1u },
		{ KGENOME_NUCLEO_NET_LISTEN, 1u },
		{ KGENOME_NUCLEO_NET_OPEN, 1u },
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
	NN_CK(rows == 61u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 1, "Invoke-Expression");
	nn_check_stable(TARGET, "Invoke-Expression");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "Invoke-Expression") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_psh_names: the rows of the PowerShell table, in the case it keeps, and the names it keeps out");
}
