/*
 * nucleo_names_bat.c - what a command of a Windows batch file (cmd.exe) means.
 *
 * A batch file has no function calls: what it asks of the system it asks by running a COMMAND, the first word of a command
 * line, and an external program is exactly as much a "name" as a built-in. So a row is the command spelled as the script
 * spells it, without the extension (the reader drops .exe, .com, .bat and .cmd: "powershell" is powershell.exe), at the
 * start of a command - after `&`, `&&`, `|`, `(`, `do`, `else`, and after `if ... ` and `start`/`call` - and never as an
 * argument or inside an `echo`. Case does not matter (`fold`). What a command does with its arguments (certutil -decode
 * against -urlcache, reg add against reg query, sc create against sc query) is the matcher's: a row names a command whose
 * act the name itself carries, and a command whose meaning is its argument is left out (see the end).
 *
 * The evidence is 45 malware batch files (35 families; droppers and downloaders) against 1122 benign ones, command-position
 * occurrences only. [Unverified: the malware batch corpus is small, so most rows are the documented command with no
 * occurrence in it, and the counts of the rows that do occur are the evidence of the others by analogy only.]
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: certutil -decode makes a file out of base64 text, which is why it is a payload decoder and not only a certificate
	 * tool; its -urlcache -f is also a download (the argument decides which: the row is the decode). 0/1122 benign, 1/45
	 * malware.
	 */
	{ .name = "certutil", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * DYNCALL: the row "(dynamic)" is a command whose NAME is a variable expansion (`%cmd% args`, `call %x%`): a callee that is
	 * a value.
	 */
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	/*
	 * PROCESS: the native word is proc-start for every one of them. A batch file runs other code by starting an interpreter or a
	 * Windows binary that runs it: powershell 3/1122 benign, 9/45 malware, cmd 1/1122 benign, 1/45 malware, and the script hosts
	 * and living-off-the-land proxies - wscript, cscript 1/1122 benign, 1/45 malware, mshta, rundll32 2/1122 benign, 0/45
	 * malware, regsvr32 1/1122 benign, 0/45 malware, msiexec 1/1122 benign, 1/45 malware, installutil, odbcconf, wmic, forfiles,
	 * runas, psexec - which run a script, a DLL or a remote command named in their arguments. [Unverified: wscript, mshta,
	 * installutil, odbcconf, wmic, forfiles, runas and psexec do not occur in this corpus.]
	 */
	{ .name = "powershell", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "pwsh", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "cmd", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "wscript", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "cscript", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "mshta", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "rundll32", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "regsvr32", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "msiexec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "installutil", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "odbcconf", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "wmic", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "forfiles", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "runas", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "psexec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "wsl", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "bash", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * FILE: permissions only. icacls, cacls and takeown change who may open a file, which is what a dropper does to make its
	 * file stay (or a wiper to reach one). [Unverified: none occurs here (icacls 0/1122 benign, 0/45 malware, takeown 0/1122
	 * benign, 0/45 malware).] The commands that create, copy, move and delete are left out below: a batch file does that on
	 * every line.
	 */
	{ .name = "icacls", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "cacls", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "takeown", .cap = KGENOME_NUCLEO_PERM_SET },
	/*
	 * NETWORK: curl is a download in the batch files that use it (0/1122 benign, 8/45 malware); bitsadmin is the BITS download
	 * tool (0/1122 benign, 1/45 malware); ftp and tftp fetch with a script file or a flag, telnet and nc connect. ftp is 6/1122
	 * benign, 2/45 malware: it is the only one here with benign use. nslookup is the one DNS lookup the shell has (0/1122
	 * benign, 0/45 malware).
	 */
	{ .name = "curl", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "bitsadmin", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "ftp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "tftp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "telnet", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "nc", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ncat", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "nslookup", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * tasklist reads the list of running processes: the question exists to find a process to kill or to avoid (0/1122 benign,
	 * 1/45 malware).
	 */
	{ .name = "tasklist", .cap = KGENOME_NUCLEO_PROC_LIST },
	/*
	 * LEFT OUT, because the name is not the evidence, with the command-position counts over the 45 malware / 1122 benign batch
	 * files: del 316/1122 benign, 3/45 malware, erase 4/1122 benign, 0/45 malware, rmdir 11/1122 benign, 1/45 malware, rd
	 * 32/1122 benign, 1/45 malware, ren 333/1122 benign, 0/45 malware, rename 5/1122 benign, 0/45 malware, move 11/1122 benign,
	 * 1/45 malware, copy 151/1122 benign, 2/45 malware, xcopy 91/1122 benign, 0/45 malware, mkdir 30/1122 benign, 5/45 malware,
	 * md 87/1122 benign, 0/45 malware, type 12/1122 benign, 0/45 malware, attrib 49/1122 benign, 0/45 malware (what a batch file
	 * does on every line is not a claim; PHP's fread and mkdir are out for the same reason); start 27/1122 benign, 6/45 malware,
	 * call 173/1122 benign, 8/45 malware, echo 354/1122 benign, 30/45 malware, set 259/1122 benign, 23/45 malware, goto 130/1122
	 * benign, 13/45 malware, if, for, exit (the language); ping 2/1122 benign, 1/45 malware, timeout 1/1122 benign, 8/45 malware
	 * (a wait: the batch way to delay a payload or retry a download, and in no benign file of the corpus but one - it is not a
	 * row because no table of this set names a wait: it is how every poll loop works, PHP's sleep is not a row either, and
	 * `sleep` is in 280/2013 benign, 69/866 malware of the shell scripts); net 6/1122 benign, 2/45 malware and sc 2/1122 benign,
	 * 1/45 malware and reg 1/1122 benign, 3/45 malware and schtasks 0/1122 benign, 2/45 malware (the verb is in the argument:
	 * net user, net use, sc create, reg add, schtasks /create are one command each with several meanings; a row would call `reg
	 * query` a registry write); the arguments of powershell (-WindowStyle Hidden, -EncodedCommand, -ExecutionPolicy Bypass) and
	 * of every other command. NOT NAMED because the vocabulary has no word: scheduled tasks (schtasks), account creation (net
	 * user), killing a process (taskkill), the firewall (netsh), and the deletion of backups and logs (vssadmin delete shadows,
	 * wevtutil cl, bcdedit) which is the ransomware's first minute.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_bat = {
	.target = KGENOME_NUCLEO_T_BAT, .fold = 1, .row = rows, .n = sizeof rows / sizeof rows[0]
};
