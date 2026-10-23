/*
 * nucleo_names_dotnet.c - what a .NET name means as an ASP.NET page runs it: the class library, from C# and from VB.NET.
 *
 * One table serves both languages of the lexer id ASPX: they call the same classes, a name is "Class.Member" with the
 * namespace left off ("Process.Start" is `System.Diagnostics.Process.Start`), and VB.NET does not care about case, so the
 * table does not either (`fold`: C# is case sensitive, but no two members of the class library differ only by case, so a
 * match that C# would refuse is a name that does not exist). A member of an object the program holds in a variable is
 * written with the CLASS ("Process.Start" for `p.Start()` after `p = new Process()`, "WebClient.DownloadString"). A
 * constructor that does the act when it is made (a TcpClient connects) is the class name alone. The ASP.NET intrinsic
 * objects are written as the page writes them ("Request.Form"). COM objects reached through Server.CreateObject or
 * Microsoft.VisualBasic's CreateObject are the VBS table's.
 *
 * The evidence is the ASP.NET shells of the corpus (6 files: cmd shells in C# and VB.NET, one of them a web service) against
 * 4840 benign C# files of this machine (a decompiled Exchange server and Kaspersky's own sources). [Unverified: that is a
 * handful of shells, so most rows are the documented API and have no malware occurrence; the benign count is large because
 * the corpus is server code and says what a server calls.]
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: Convert.FromBase64String (22/4840 benign, 0/6 malware), the compression streams, and the url decoders
	 * (HttpUtility.UrlDecode 8/4840 benign, 0/6 malware). With a key: the symmetric algorithms and the stream that applies them;
	 * CryptoStream is the common point (1/4840 benign, 0/6 malware). [Unverified: no malware occurrence.]
	 */
	{ .name = "Convert.FromBase64String", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Convert.FromHexString", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "GZipStream", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "DeflateStream", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "HttpUtility.UrlDecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "WebUtility.UrlDecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Uri.UnescapeDataString", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "CryptoStream", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "AesManaged.CreateDecryptor", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "Aes.CreateDecryptor", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "RijndaelManaged.CreateDecryptor", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "TripleDESCryptoServiceProvider.CreateDecryptor", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "DESCryptoServiceProvider.CreateDecryptor", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * EVAL: text run as code, now: JScript's eval through Microsoft.JScript (the old ASP.NET way: Eval.JScriptEvaluate) and
	 * Roslyn's scripting. CREATE: source text compiled into an assembly (CSharpCodeProvider and VBCodeProvider,
	 * CodeDomProvider.CompileAssemblyFromSource) or emitted (DynamicMethod, AssemblyBuilder): the aspx shells that compile their
	 * payload at request time. DYNCALL: Method.Invoke and Delegate.DynamicInvoke call what they were handed, and InvokeMember
	 * calls a member by its name; the row "(dynamic)" is a call of a value (a delegate variable the program did not write as a
	 * name). DYNLOAD: a class made out of a name or bytes - Assembly.Load of bytes is how a loader runs an assembly it carries;
	 * Activator.CreateInstance and Type.GetType take a name; the row "(load)" is `Activator.CreateInstance(t)` with t from a
	 * value. [Unverified: none of these occurs in a malware file here; Activator.CreateInstance is 15/4840 benign, 0/6 malware,
	 * which is why its class-name form alone is not a claim.]
	 */
	{ .name = "Eval.JScriptEvaluate", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "JScriptEvaluate", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "CSharpScript.EvaluateAsync", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "CSharpCodeProvider.CompileAssemblyFromSource", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "VBCodeProvider.CompileAssemblyFromSource", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "CodeDomProvider.CompileAssemblyFromSource", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "CodeDomProvider.CompileAssemblyFromFile", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "DynamicMethod", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "AssemblyBuilder.DefineDynamicAssembly", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "CSharpScript.Create", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "MethodInfo.Invoke", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "Delegate.DynamicInvoke", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "Type.InvokeMember", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "Assembly.Load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Assembly.LoadFrom", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Assembly.LoadFile", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Assembly.UnsafeLoadFrom", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Assembly.LoadWithPartialName", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "AppDomain.Load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Type.GetType", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Activator.CreateInstance", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Type.GetTypeFromProgID", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: a native library opened by DllImport (5/4840 benign, 0/6 malware) or NativeLibrary.Load. [Unverified: no malware
	 * occurrence.]
	 */
	{ .name = "DllImport", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "NativeLibrary.Load", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender of the request chose - the collections of Request: Form 5/4840 benign, 2/6 malware, QueryString
	 * 43/4840 benign, 0/6 malware, Params, Files, Cookies, Item, Headers, InputStream and BinaryRead. Request.Form is in two of
	 * the malware files and in a handful of benign ones (a server reads its request: the claim is the join with an execution).
	 */
	{ .name = "Request.Form", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.QueryString", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Params", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Files", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Cookies", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Item", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.Headers", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.InputStream", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "Request.BinaryRead", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. Process.Start is 1/4840 benign, 2/6 malware and
	 * ProcessStartInfo is the object every cmd shell builds (1/4840 benign, 6/6 malware); the row is Process.Start and the start
	 * info with a file name is the matcher's. [Unverified: against a larger set.]
	 */
	{ .name = "Process.Start", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ProcessStartInfo", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * FILE: what a shell's file manager does and what a dropper does with its file: open to read (File.ReadAllText 3/4840
	 * benign, 0/6 malware, ReadAllBytes, OpenRead), write (WriteAllBytes, WriteAllText, AppendAllText, Create, OpenWrite, the
	 * upload's SaveAs), copy, delete 4/4840 benign, 0/6 malware, move, set attributes and times. File.Exists, Directory.GetFiles
	 * and the readers and writers of a stream are far too common to be rows.
	 */
	{ .name = "File.ReadAllText", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "File.ReadAllBytes", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "File.ReadAllLines", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "File.OpenRead", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "File.Open", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "File.WriteAllText", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.WriteAllBytes", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.AppendAllText", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.Create", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.OpenWrite", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.Copy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "FileInfo.CopyTo", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "HttpPostedFile.SaveAs", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.Delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "Directory.Delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "FileInfo.Delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "DirectoryInfo.Delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "File.Move", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "Directory.Move", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "FileInfo.MoveTo", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "File.SetAttributes", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "File.SetLastWriteTime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "File.SetCreationTime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	/*
	 * NETWORK: TcpClient and Socket connect, TcpListener listens, UdpClient opens (0/4840 benign, 0/6 malware); WebClient
	 * fetches with its Download calls and sends with its Upload calls (5/4840 benign, 0/6 malware: constructed, 0/4840 benign,
	 * 0/6 malware as the call); HttpWebRequest's Create and HttpClient's calls are the HTTP clients. DNS: the Dns class's
	 * lookups.
	 */
	{ .name = "TcpClient", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Socket", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "TcpListener", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "UdpClient", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "WebClient", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "HttpClient", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "WebClient.DownloadString", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "WebClient.DownloadFile", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "WebClient.DownloadData", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "WebRequest.Create", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "HttpClient.GetAsync", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "HttpClient.GetStringAsync", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "WebClient.UploadString", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "WebClient.UploadFile", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "WebClient.UploadData", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "HttpClient.PostAsync", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "Dns.GetHostEntry", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Dns.GetHostAddresses", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Dns.GetHostByName", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Dns.Resolve", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * REGISTRY: writes only. Registry.SetValue and RegistryKey.SetValue; CreateSubKey makes the key that precedes the value.
	 * [Unverified: no occurrence.]
	 */
	{ .name = "Registry.SetValue", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegistryKey.SetValue", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegistryKey.CreateSubKey", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegistryKey.DeleteValue", .cap = KGENOME_NUCLEO_REG_SET },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 6 malware / 4840 benign files: Request
	 * 335/4840 benign, 0/6 malware alone, Request.ServerVariables 3/4840 benign, 0/6 malware, Request.Url, Request.RawUrl,
	 * Request.UserAgent 22/4840 benign, 0/6 malware (the page's own request metadata, as PHP's $_SERVER); Server.MapPath 1/4840
	 * benign, 0/6 malware; File.Exists 22/4840 benign, 0/6 malware, FileStream 17/4840 benign, 0/6 malware, StreamReader 25/4840
	 * benign, 4/6 malware, StreamWriter 14/4840 benign, 0/6 malware, Directory.GetFiles 4/4840 benign, 0/6 malware,
	 * Directory.CreateDirectory (every program that touches a file); Thread.Sleep 10/4840 benign, 0/6 malware,
	 * Environment.MachineName, Environment.Exit; Convert.ToBase64String and the encoders; Encoding.UTF8.GetString 4/4840 benign,
	 * 0/6 malware (the byte-to-text step after a decode); Process.GetProcessesByName, Process.GetProcesses and Process.Kill;
	 * MD5.Create and the hashes; the whole of ADO.NET, SmtpClient. NOT NAMED because the vocabulary has no word: a registry
	 * read. NOT ADDED for lack of an occurrence although the vocabulary has the word: the process list (Process.GetProcesses is
	 * proc-list), Debugger.IsAttached (anti-debug) and the service installer (ManagedInstallerClass.InstallHelper is
	 * svc-install).
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_dotnet = {
	.target = KGENOME_NUCLEO_T_DOTNET, .fold = 1, .row = rows, .n = sizeof rows / sizeof rows[0]
};
