/*
 * nucleo_names_vbs.c - what a VBScript name means: the language's own statements, the Windows Script Host and the COM
 * objects a script creates, and classic ASP's Request/Response/Server.
 *
 * A VBScript program does almost nothing itself: it asks COM. So the identity of a call is the class of the OBJECT, and a
 * row is "ProgID.Member" (the convention in nucleo.h): `Set o = CreateObject("WScript.Shell")` then `o.Run cmd` is
 * "WScript.Shell.Run", wherever the variable `o` came from. The same COM objects are reached from JScript (`new
 * ActiveXObject`), from PowerShell (`New-Object -ComObject`) and from ASP (`Server.CreateObject`), so they are written ONCE,
 * here, and the tables of those languages do not repeat them. One table serves the lexer ids VBS and ASP: classic ASP runs
 * VBScript, and its Request / Response / Server objects are the same objects when the page is JScript. VBScript does not
 * care about case (`fold`); a ProgID is written without its version number ("MSXML2.XMLHTTP.6.0" is "MSXML2.XMLHTTP").
 *
 * The evidence is the VBScript of 141 malware files (cmd shells, droppers and downloaders of the WSH family) and, for the
 * page objects, the 20 classic ASP shells of the corpus; against it 19 ordinary VBScript files and 135 benign .asp files.
 * [Unverified: the benign sets are small - this machine holds 19 distinct .vbs files - and the benign .asp files are router
 * firmware pages (ASUS) that use none of Request, Response or CreateObject, so a benign count of 0 for the page objects says
 * "not seen", not "never".] Rows without a measured occurrence say so.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: bytes made out of other bytes with no key. StrReverse is how a name or an URL is kept out of a string scan (0/19
	 * benign, 18/141 malware); .nodeTypedValue of an XML element whose dataType was set to bin.base64 or bin.hex is the VBScript
	 * way to decode base64 (2/19 benign, 32/141 malware). VBScript has no base64 function of its own.
	 */
	{ .name = "StrReverse", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "nodeTypedValue", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * EVAL: Execute and ExecuteGlobal run text now, and Eval evaluates an expression: the statement forms, not the members -
	 * `conn.Execute(sql)` is a database call and is a different name (ADODB.Connection.Execute, which the vocabulary has no word
	 * for). ExecuteGlobal 0/19 benign, 39/141 malware and Execute 0/19 benign, 13/141 malware are the last step of the
	 * obfuscated droppers. The ScriptControl rows are the same act through the MSScriptControl COM object. [Unverified: no
	 * sample here uses the ScriptControl; the rows are the documented way to evaluate text from a script that has no Eval.]
	 */
	{ .name = "Execute", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "ExecuteGlobal", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "Eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "MSScriptControl.ScriptControl.Eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "MSScriptControl.ScriptControl.ExecuteStatement", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "MSScriptControl.ScriptControl.AddCode", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "MSScriptControl.ScriptControl.Run", .cap = KGENOME_NUCLEO_DYNCALL },
	/*
	 * DYNCALL: GetRef turns the NAME of a procedure into something callable, and a call through the handle is a call whose
	 * callee is a value. [Unverified: 0 in the corpus; VBScript has no other way to call something by a string.] The row
	 * "(dynamic)" is the call of that handle, and "(load)" is `CreateObject(x)` with x not a literal: a class named by a value.
	 */
	{ .name = "GetRef", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * REQUEST: what the sender of an ASP request chose. Request alone is the default collection, `Request("x")`; Form,
	 * QueryString and Cookies are the collections, and BinaryRead is the body of an upload. In the ASP shells: Request.Form
	 * 0/135 benign, 12/20 malware, Request.QueryString 0/135 benign, 7/20 malware, Request 0/135 benign, 6/20 malware,
	 * Request.BinaryRead 0/135 benign, 4/20 malware. None of them occurs in the benign .asp files here.
	 */
	{ .name = "Request", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Form", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.QueryString", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Cookies", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.BinaryRead", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. WScript.Shell.Run is the cmd shells and the droppers 1/19
	 * benign, 19/141 malware; .Exec is the form that hands back the output 0/19 benign, 3/141 malware (0/135 benign, 6/20
	 * malware ASP shells). Shell.Application.ShellExecute starts a program through the shell 0/19 benign, 5/141 malware.
	 * Win32_Process.Create is WMI starting a process; the class name is spelled in a string and never as a token here, so the
	 * corpus cannot count it, but the JavaScript downloader family of the corpus builds the string "Win32_Process" piece by
	 * piece to call it (the member SpawnInstance_ of its startup object: 0/3286 benign, 13/1356 malware). [Unverified as a
	 * VBScript row: the evidence is JScript.]
	 */
	{ .name = "WScript.Shell.Run", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "WScript.Shell.Exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Shell.Application.ShellExecute", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Win32_Process.Create", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * FILE: what a file manager does. Scripting.FileSystemObject: OpenTextFile reads or writes by its mode, CreateTextFile
	 * writes 1/19 benign, 20/141 malware, DeleteFile and DeleteFolder remove 2/19 benign, 6/141 malware, MoveFile and MoveFolder
	 * rename, CopyFile and CopyFolder copy. ADODB.Stream is how a script writes BINARY data (an HTTP body, a decoded payload) to
	 * a file: SaveToFile 0/19 benign, 5/141 malware, and LoadFromFile reads one back. Where a method opens and a mode decides,
	 * the word is the opening one, as for PHP's fopen.
	 */
	{ .name = "Scripting.FileSystemObject.OpenTextFile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "ADODB.Stream.LoadFromFile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "Scripting.FileSystemObject.CreateTextFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "Scripting.FileSystemObject.CopyFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "Scripting.FileSystemObject.CopyFolder", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "ADODB.Stream.SaveToFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "Scripting.FileSystemObject.DeleteFile", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "Scripting.FileSystemObject.DeleteFolder", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "Scripting.FileSystemObject.MoveFile", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "Scripting.FileSystemObject.MoveFolder", .cap = KGENOME_NUCLEO_FILE_RENAME },
	/*
	 * HTTP: the XMLHTTP family is the only HTTP client a script has without a download tool. Open names the URL (the word
	 * http-connect is the one that names an endpoint), Send sends, and the response properties are what comes back. Four
	 * ProgIDs, one act each: MSXML2.XMLHTTP 0/19 benign, 4/141 malware, Microsoft.XMLHTTP 0/19 benign, 0/141 malware,
	 * MSXML2.ServerXMLHTTP 0/19 benign, 2/141 malware and WinHttp.WinHttpRequest 1/19 benign, 4/141 malware (counted as: the
	 * ProgID and the member in the same file).
	 */
	{ .name = "MSXML2.XMLHTTP.Open", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "Microsoft.XMLHTTP.Open", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "MSXML2.ServerXMLHTTP.Open", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "WinHttp.WinHttpRequest.Open", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "MSXML2.XMLHTTP.Send", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "Microsoft.XMLHTTP.Send", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "MSXML2.ServerXMLHTTP.Send", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "WinHttp.WinHttpRequest.Send", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "MSXML2.XMLHTTP.ResponseText", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "MSXML2.XMLHTTP.ResponseBody", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "Microsoft.XMLHTTP.ResponseText", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "Microsoft.XMLHTTP.ResponseBody", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "MSXML2.ServerXMLHTTP.ResponseText", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "MSXML2.ServerXMLHTTP.ResponseBody", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "WinHttp.WinHttpRequest.ResponseText", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "WinHttp.WinHttpRequest.ResponseBody", .cap = KGENOME_NUCLEO_HTTP_RECV },
	/*
	 * REGISTRY: writes only, as in the native table (a script reading its own settings is every script). RegWrite is the Run key
	 * of a dropper. 1/19 benign, 1/141 malware.
	 */
	{ .name = "WScript.Shell.RegWrite", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "WScript.Shell.RegDelete", .cap = KGENOME_NUCLEO_REG_SET },
	/*
	 * ASP loads another page into this one, which is the same act as include: the operand is what makes it a shell. [Unverified:
	 * none of the 20 ASP shells uses them.]
	 */
	{ .name = "Server.Execute", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "Server.Transfer", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * LEFT OUT, because the name is not the evidence (the same rule as the native table), with the file counts of the 141
	 * malware / 19 benign VBScript files: Chr 2/19 benign, 109/141 malware, ChrW 0/19 benign, 12/141 malware, Asc 0/19 benign,
	 * 59/141 malware (a byte made from a number: how every VBScript builds a string, as PHP's chr), Mid 7/19 benign, 58/141
	 * malware, Replace 2/19 benign, 79/141 malware, Split 3/19 benign, 22/141 malware, Join 2/19 benign, 21/141 malware (string
	 * handling of every script); CreateObject with a literal ProgID 7/19 benign, 116/141 malware and WScript.CreateObject 11/19
	 * benign, 27/141 malware (the creation says nothing, the methods called on the object do); GetObject 1/19 benign, 8/141
	 * malware; WScript.Sleep 0/19 benign, 16/141 malware (a wait is how every poll loop works and no table of this set names
	 * one; the best candidate if the vocabulary wants a sandbox delay: in no benign file here) and WScript.Quit 11/19 benign,
	 * 39/141 malware; WScript.Arguments 12/19 benign, 1/141 malware (the command line of a script is not a request);
	 * WScript.ScriptFullName 1/19 benign, 12/141 malware, WScript.Network UserName and ComputerName (host identity, as
	 * GetComputerName in the native table); Scripting.FileSystemObject FileExists, FolderExists, GetFolder, GetFile,
	 * GetTempName, GetSpecialFolder, ReadAll, ReadLine, WriteLine (probing and the stream half of a file the open already
	 * named); WScript.Shell.RegRead 1/19 benign, 5/141 malware (reads are every program); WScript.Shell.Environment and
	 * ExpandEnvironmentStrings; Request.ServerVariables 0/135 benign, 16/20 malware (the ASP shells read it to write their own
	 * form action: the page's own URL is not what the sender chose), Request.TotalBytes, Response.Write 0/135 benign, 19/20
	 * malware and the rest of Response; ADODB.Connection and ADODB.Recordset (a database is not in the vocabulary); MsgBox,
	 * Echo, Timer, Now, DateAdd. NOT NAMED because the vocabulary has no word: the Task Scheduler COM object (Schedule.Service:
	 * persistence), WScript.Shell.CreateShortcut, and ShowWindow = 0 or window.moveTo to hide a window (the HTA family of
	 * nucleo_names_js.c).
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_vbs = {
	.target = KGENOME_NUCLEO_T_VBS, .fold = 1, .row = rows, .n = sizeof rows / sizeof rows[0]
};
