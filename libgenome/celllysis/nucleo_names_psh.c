/*
 * nucleo_names_psh.c - what a PowerShell name means: the cmdlets and the .NET classes a script reaches from them, in the
 * vocabulary a native program's imports are read in.
 *
 * PowerShell does not care about case (`fold`). A cmdlet is its name ("Invoke-Expression"); a static member or a constructor
 * of a .NET class is written "Class.Member" with the class the way the script spells it inside the brackets and without the
 * leading "System." ("[System.Convert]::FromBase64String" and "[Convert]::FromBase64String" are both
 * "Convert.FromBase64String"; `New-Object System.Net.WebClient` is "Net.WebClient"). A member of an object the script holds
 * in a variable is written with the class too, so `$wc.DownloadString(...)` after `$wc = New-Object Net.WebClient` is
 * "Net.WebClient.DownloadString". A native command is its name without its extension ("powershell" for powershell.exe). THE
 * COM OBJECTS reached by `New-Object -ComObject` are not here: they are the VBS table's, written once ("WScript.Shell.Run").
 *
 * The evidence is 78 malware files (43 families by the tokens they share; downloaders, stagers and ransomware scripts)
 * against 59 benign files (PowerShell Editor Services modules and examples, installers). [Unverified: both sets are small,
 * and the benign set is mostly module code, so a benign count of 0 is "not seen"; many rows are the documented API and have
 * no occurrence in either set, and say so.]
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: Convert.FromBase64String is the step between where a payload is kept and where it runs (3/59 benign, 12/78
	 * malware). The compression streams are the other half of a packed stager: GzipStream and DeflateStream take the compressed
	 * bytes and, read, give the payload. [Unverified: the stream rows have no malware occurrence here (GzipStream 1/59 benign,
	 * 0/78 malware, DeflateStream 0/59 benign, 0/78 malware); they are what a stager written without a decoder of its own uses.]
	 */
	{ .name = "Convert.FromBase64String", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "IO.Compression.GzipStream", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "IO.Compression.DeflateStream", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * EVAL: Invoke-Expression and its alias iex run text now: 0/59 benign, 28/78 malware, iex 0/59 benign, 3/78 malware.
	 * InvokeScript of the engine's command invocation is the same act through the host object. CREATE: a script block made from
	 * text (ScriptBlock.Create) is a function that is called later; Add-Type compiles C# source into types 6/59 benign, 5/78
	 * malware. DYNCALL: Invoke is the call of a script block or a method object held in a variable (1/59 benign, 31/78 malware:
	 * the commonest call of the stagers here), and "(dynamic)" is `& $x` and `. $x`, a call of a value (only a call whose
	 * operand is not a name the program wrote is the row: `& "C:\x.exe"` is a process start by name).
	 */
	{ .name = "Invoke-Expression", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "iex", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "InvokeCommand.InvokeScript", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "ScriptBlock.Create", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "Add-Type", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "Invoke", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	/*
	 * DYNLOAD: an assembly loaded from bytes or a name - Reflection.Assembly.Load is how a stager runs a .NET payload without a
	 * file (the class Reflection.Assembly is in 0/59 benign, 3/78 malware) - and the row "(load)", `New-Object $type`,
	 * `[Type]::GetType($name)` or `Add-Type -AssemblyName $x`: a class named by a value. New-Object with a literal class is in
	 * 19/59 benign, 45/78 malware and is not a row.
	 */
	{ .name = "Reflection.Assembly.Load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Reflection.Assembly.LoadFile", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Reflection.Assembly.LoadFrom", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Reflection.Assembly.LoadWithPartialName", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * PROCESS: the native word is proc-start for every one of them. Start-Process 7/59 benign, 8/78 malware; the interpreters
	 * and the Windows binaries a script runs other code through, named as native commands: powershell 0/59 benign, 13/78
	 * malware, cmd 2/59 benign, 2/78 malware, and the script hosts and proxies (wscript, cscript, mshta, rundll32, regsvr32)
	 * which are the same act. [Unverified: wscript, cscript, mshta, rundll32 and regsvr32 do not occur in this PowerShell
	 * corpus; they are the documented hosts a script starts to run code that is not PowerShell.]
	 */
	{ .name = "Start-Process", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Diagnostics.Process.Start", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "powershell", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "pwsh", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "cmd", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "wscript", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "cscript", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "mshta", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "rundll32", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "regsvr32", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * FILE: what a dropper does with a file - write it (Set-Content 1/59 benign, 4/78 malware, Add-Content, the .NET writers),
	 * move it, and read it back. The ordinary cmdlets are left out below; the .NET calls and Move-Item are here as the dropper's
	 * spelling. [Unverified: none of the .NET rows occurs in the corpus.]
	 */
	{ .name = "IO.File.ReadAllBytes", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "IO.File.ReadAllText", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "Set-Content", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "Add-Content", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "IO.File.WriteAllBytes", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "IO.File.WriteAllText", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "IO.File.AppendAllText", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "IO.File.Delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "Move-Item", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "Rename-Item", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "Set-Acl", .cap = KGENOME_NUCLEO_PERM_SET },
	/*
	 * REGISTRY: writes only, as in the native table. Set-ItemProperty is the cmdlet that writes a registry value (and a file
	 * attribute: the registry is what it is used for here: Set-ItemProperty 0/59 benign, 4/78 malware against Get-ItemProperty
	 * 0/59 benign, 3/78 malware for the read). New-Service installs one.
	 */
	{ .name = "Set-ItemProperty", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "New-ItemProperty", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "Remove-ItemProperty", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "New-Service", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	/*
	 * NETWORK: Invoke-WebRequest and Invoke-RestMethod fetch a URL in one call (the word the native table gives
	 * URLDownloadToFile), with their aliases (3/59 benign, 4/78 malware, iwr 0/59 benign, 1/78 malware; curl and wget are
	 * aliases of it in Windows PowerShell). The WebClient is the class every download cradle starts from (6/59 benign, 8/78
	 * malware); its Download calls fetch, its Upload calls send. A TcpClient connects when it is constructed with a host, which
	 * is the whole of a PowerShell reverse shell (0/59 benign, 1/78 malware).
	 */
	{ .name = "Invoke-WebRequest", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "iwr", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Invoke-RestMethod", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "irm", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "curl", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "wget", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Start-BitsTransfer", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Net.WebClient.DownloadString", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Net.WebClient.DownloadFile", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Net.WebClient.DownloadData", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Net.WebClient", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "Net.WebClient.UploadString", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "Net.WebClient.UploadFile", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "Net.WebClient.UploadData", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "Net.Sockets.TcpClient", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Net.Sockets.TcpListener", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "Net.Sockets.UdpClient", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "Resolve-DnsName", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Net.Dns.GetHostAddresses", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Net.Dns.GetHostEntry", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Net.Dns.GetHostByName", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 78 malware / 59 benign files: Start-Sleep 6/59
	 * benign, 20/78 malware (a wait is how every retry loop works); Get-Content 9/59 benign, 2/78 malware, Out-File 1/59 benign,
	 * 1/78 malware, Remove-Item 13/59 benign, 10/78 malware, Copy-Item 8/59 benign, 9/78 malware, New-Item 8/59 benign, 16/78
	 * malware, Get-ChildItem 5/59 benign, 4/78 malware, Get-ItemProperty 0/59 benign, 3/78 malware (the cmdlets every
	 * administration script calls); Get-Process 2/59 benign, 5/78 malware, Get-WmiObject 1/59 benign, 3/78 malware,
	 * Get-CimInstance 3/59 benign, 2/78 malware, Invoke-CimMethod 0/59 benign, 0/78 malware; New-Object 19/59 benign, 45/78
	 * malware, Import-Module 6/59 benign, 0/78 malware; param 32/59 benign, 37/78 malware, $args 12/59 benign, 30/78 malware, $_
	 * 11/59 benign, 13/78 malware (the arguments of a script are not a request: PowerShell has no request source row);
	 * Write-Host 19/59 benign, 15/78 malware; the operators -bxor 0/59 benign, 33/78 malware, -join 6/59 benign, 12/78 malware,
	 * -replace 7/59 benign, 29/78 malware, -split 9/59 benign, 8/78 malware and -f (an XOR loop with a key is the decode of a
	 * good part of the stagers here (-bxor is in two in five of the malware files) and has no call syntax: it is an operator, so
	 * the join - a decode that reaches Invoke-Expression - is what finds it), [char], GetString of a text encoding 4/59 benign,
	 * 39/78 malware (the byte-to-text step after the base64 one); Invoke-Command; the ARGUMENTS of the powershell command
	 * (-WindowStyle Hidden 0/59 benign, 14/78 malware, -EncodedCommand, -NoProfile 0/59 benign, 6/78 malware, -ExecutionPolicy
	 * Bypass); Stop-Process 0/59 benign, 5/78 malware, Register-ScheduledTask and schtasks 1/59 benign, 6/78 malware
	 * (persistence), Set-MpPreference and Add-MpPreference (disabling the antivirus), Set-ExecutionPolicy: NOT NAMED because the
	 * vocabulary has no word for killing a process, a scheduled task or an exclusion in the antivirus.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_psh = {
	.target = KGENOME_NUCLEO_T_PSH, .fold = 1, .row = rows, .n = sizeof rows / sizeof rows[0]
};
