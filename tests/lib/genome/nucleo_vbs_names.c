/*
 * nucleo_vbs_names - the rows of the VBScript and classic ASP table, and the names it keeps out
 * (libgenome/celllysis/nucleo_names_vbs.c): every row resolves to its capability and gives its own name back through its id,
 * the capability of every row is counted (a row moved to another word, added or dropped changes a count), the names the table
 * keeps OUT on purpose resolve to nothing, and the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every VBScript and classic ASP program there is. Each is
 * pinned here with the file count that decided it - in the 19 benign / 141 malware files the table was measured on (the
 * measurement and its limits are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_VBS

int main(void)
{
	static const struct nn_is is[] = {
		{ "StrReverse", KGENOME_NUCLEO_DECODE },
		{ "nodeTypedValue", KGENOME_NUCLEO_DECODE },
		{ "Execute", KGENOME_NUCLEO_EVAL },
		{ "ExecuteGlobal", KGENOME_NUCLEO_EVAL },
		{ "Eval", KGENOME_NUCLEO_EVAL },
		{ "MSScriptControl.ScriptControl.Eval", KGENOME_NUCLEO_EVAL },
		{ "MSScriptControl.ScriptControl.ExecuteStatement", KGENOME_NUCLEO_EVAL },
		{ "MSScriptControl.ScriptControl.AddCode", KGENOME_NUCLEO_CREATE },
		{ "MSScriptControl.ScriptControl.Run", KGENOME_NUCLEO_DYNCALL },
		{ "GetRef", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "Request", KGENOME_NUCLEO_REQUEST },
		{ "Request.Form", KGENOME_NUCLEO_REQUEST },
		{ "Request.QueryString", KGENOME_NUCLEO_REQUEST },
		{ "Request.Cookies", KGENOME_NUCLEO_REQUEST },
		{ "Request.BinaryRead", KGENOME_NUCLEO_REQUEST },
		{ "WScript.Shell.Run", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "WScript.Shell.Exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Shell.Application.ShellExecute", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Win32_Process.Create", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "Scripting.FileSystemObject.OpenTextFile", KGENOME_NUCLEO_FILE_OPEN },
		{ "ADODB.Stream.LoadFromFile", KGENOME_NUCLEO_FILE_OPEN },
		{ "Scripting.FileSystemObject.CreateTextFile", KGENOME_NUCLEO_WRITE },
		{ "Scripting.FileSystemObject.CopyFile", KGENOME_NUCLEO_WRITE },
		{ "Scripting.FileSystemObject.CopyFolder", KGENOME_NUCLEO_WRITE },
		{ "ADODB.Stream.SaveToFile", KGENOME_NUCLEO_WRITE },
		{ "Scripting.FileSystemObject.DeleteFile", KGENOME_NUCLEO_FILE_DELETE },
		{ "Scripting.FileSystemObject.DeleteFolder", KGENOME_NUCLEO_FILE_DELETE },
		{ "Scripting.FileSystemObject.MoveFile", KGENOME_NUCLEO_FILE_RENAME },
		{ "Scripting.FileSystemObject.MoveFolder", KGENOME_NUCLEO_FILE_RENAME },
		{ "MSXML2.XMLHTTP.Open", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "Microsoft.XMLHTTP.Open", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "MSXML2.ServerXMLHTTP.Open", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "WinHttp.WinHttpRequest.Open", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "MSXML2.XMLHTTP.Send", KGENOME_NUCLEO_HTTP_SEND },
		{ "Microsoft.XMLHTTP.Send", KGENOME_NUCLEO_HTTP_SEND },
		{ "MSXML2.ServerXMLHTTP.Send", KGENOME_NUCLEO_HTTP_SEND },
		{ "WinHttp.WinHttpRequest.Send", KGENOME_NUCLEO_HTTP_SEND },
		{ "MSXML2.XMLHTTP.ResponseText", KGENOME_NUCLEO_HTTP_RECV },
		{ "MSXML2.XMLHTTP.ResponseBody", KGENOME_NUCLEO_HTTP_RECV },
		{ "Microsoft.XMLHTTP.ResponseText", KGENOME_NUCLEO_HTTP_RECV },
		{ "Microsoft.XMLHTTP.ResponseBody", KGENOME_NUCLEO_HTTP_RECV },
		{ "MSXML2.ServerXMLHTTP.ResponseText", KGENOME_NUCLEO_HTTP_RECV },
		{ "MSXML2.ServerXMLHTTP.ResponseBody", KGENOME_NUCLEO_HTTP_RECV },
		{ "WinHttp.WinHttpRequest.ResponseText", KGENOME_NUCLEO_HTTP_RECV },
		{ "WinHttp.WinHttpRequest.ResponseBody", KGENOME_NUCLEO_HTTP_RECV },
		{ "WScript.Shell.RegWrite", KGENOME_NUCLEO_REG_SET },
		{ "WScript.Shell.RegDelete", KGENOME_NUCLEO_REG_SET },
		{ "Server.Execute", KGENOME_NUCLEO_LIB_OPEN },
		{ "Server.Transfer", KGENOME_NUCLEO_LIB_OPEN },
	};
	/* kept out on purpose; files of 19 benign / 141 malware that call it */
	static const struct nn_out out[] = {
		{ "Chr", "2 / 109" },
		{ "ChrW", "0 / 12" },
		{ "Asc", "0 / 59" },
		{ "Mid", "7 / 58" },
		{ "Replace", "2 / 79" },
		{ "Split", "3 / 22" },
		{ "Join", "2 / 21" },
		{ "CreateObject", "7 / 116" },
		{ "WScript.CreateObject", "11 / 27" },
		{ "GetObject", "1 / 8" },
		{ "WScript.Sleep", "0 / 16" },
		{ "WScript.Quit", "11 / 39" },
		{ "WScript.Arguments", "12 / 1" },
		{ "WScript.Shell.RegRead", "1 / 5" },
		{ "Request.ServerVariables", "0 / 0" },
		{ "Response.Write", "0 / 0" },
		{ "Scripting.FileSystemObject.FileExists", "3 / 31" },
		{ "Scripting.FileSystemObject.GetFolder", "2 / 1" },
		{ "MsgBox", "1 / 4" },
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
		"child_process.exec",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"StrReverse",
		"nodeTypedValue",
		"ExecuteGlobal",
		"WScript.Shell.Run",
		"Scripting.FileSystemObject.CreateTextFile",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 2u },
		{ KGENOME_NUCLEO_EVAL, 5u },
		{ KGENOME_NUCLEO_CREATE, 1u },
		{ KGENOME_NUCLEO_DYNCALL, 3u },
		{ KGENOME_NUCLEO_DYNLOAD, 1u },
		{ KGENOME_NUCLEO_REQUEST, 5u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 4u },
		{ KGENOME_NUCLEO_FILE_OPEN, 2u },
		{ KGENOME_NUCLEO_WRITE, 4u },
		{ KGENOME_NUCLEO_FILE_DELETE, 2u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_HTTP_CONNECT, 4u },
		{ KGENOME_NUCLEO_HTTP_SEND, 4u },
		{ KGENOME_NUCLEO_HTTP_RECV, 8u },
		{ KGENOME_NUCLEO_REG_SET, 2u },
		{ KGENOME_NUCLEO_LIB_OPEN, 2u },
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
	nn_check_fold(TARGET, 1, "WScript.Shell.Run");
	nn_check_stable(TARGET, "WScript.Shell.Run");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "WScript.Shell.Run") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_vbs_names: the rows of the VBScript and classic ASP table, in the case it keeps, and the names it keeps out");
}
