/*
 * nucleo_dotnet_names - the rows of the .NET (ASP.NET) table, and the names it keeps out
 * (libgenome/celllysis/nucleo_names_dotnet.c): every row resolves to its capability and gives its own name back through its id,
 * the capability of every row is counted (a row moved to another word, added or dropped changes a count), the names the table
 * keeps OUT on purpose resolve to nothing, and the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every .NET program there is. Each is pinned here with the file
 * count that decided it - in the 4840 benign / 6 malware files the table was measured on (the measurement and its limits are in
 * the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_DOTNET

int main(void)
{
	static const struct nn_is is[] = {
		{ "Convert.FromBase64String", KGENOME_NUCLEO_DECODE },
		{ "Convert.FromHexString", KGENOME_NUCLEO_DECODE },
		{ "GZipStream", KGENOME_NUCLEO_DECODE },
		{ "DeflateStream", KGENOME_NUCLEO_DECODE },
		{ "HttpUtility.UrlDecode", KGENOME_NUCLEO_DECODE },
		{ "WebUtility.UrlDecode", KGENOME_NUCLEO_DECODE },
		{ "Uri.UnescapeDataString", KGENOME_NUCLEO_DECODE },
		{ "CryptoStream", KGENOME_NUCLEO_CRYPTO },
		{ "AesManaged.CreateDecryptor", KGENOME_NUCLEO_CRYPTO },
		{ "Aes.CreateDecryptor", KGENOME_NUCLEO_CRYPTO },
		{ "RijndaelManaged.CreateDecryptor", KGENOME_NUCLEO_CRYPTO },
		{ "TripleDESCryptoServiceProvider.CreateDecryptor", KGENOME_NUCLEO_CRYPTO },
		{ "DESCryptoServiceProvider.CreateDecryptor", KGENOME_NUCLEO_CRYPTO },
		{ "Eval.JScriptEvaluate", KGENOME_NUCLEO_EVAL },
		{ "JScriptEvaluate", KGENOME_NUCLEO_EVAL },
		{ "CSharpScript.EvaluateAsync", KGENOME_NUCLEO_EVAL },
		{ "CSharpCodeProvider.CompileAssemblyFromSource", KGENOME_NUCLEO_CREATE },
		{ "VBCodeProvider.CompileAssemblyFromSource", KGENOME_NUCLEO_CREATE },
		{ "CodeDomProvider.CompileAssemblyFromSource", KGENOME_NUCLEO_CREATE },
		{ "CodeDomProvider.CompileAssemblyFromFile", KGENOME_NUCLEO_CREATE },
		{ "DynamicMethod", KGENOME_NUCLEO_CREATE },
		{ "AssemblyBuilder.DefineDynamicAssembly", KGENOME_NUCLEO_CREATE },
		{ "CSharpScript.Create", KGENOME_NUCLEO_CREATE },
		{ "MethodInfo.Invoke", KGENOME_NUCLEO_DYNCALL },
		{ "Delegate.DynamicInvoke", KGENOME_NUCLEO_DYNCALL },
		{ "Type.InvokeMember", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "Assembly.Load", KGENOME_NUCLEO_DYNLOAD },
		{ "Assembly.LoadFrom", KGENOME_NUCLEO_DYNLOAD },
		{ "Assembly.LoadFile", KGENOME_NUCLEO_DYNLOAD },
		{ "Assembly.UnsafeLoadFrom", KGENOME_NUCLEO_DYNLOAD },
		{ "Assembly.LoadWithPartialName", KGENOME_NUCLEO_DYNLOAD },
		{ "AppDomain.Load", KGENOME_NUCLEO_DYNLOAD },
		{ "Type.GetType", KGENOME_NUCLEO_DYNLOAD },
		{ "Activator.CreateInstance", KGENOME_NUCLEO_DYNLOAD },
		{ "Type.GetTypeFromProgID", KGENOME_NUCLEO_DYNLOAD },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "DllImport", KGENOME_NUCLEO_LIB_OPEN },
		{ "NativeLibrary.Load", KGENOME_NUCLEO_LIB_OPEN },
		{ "Request.Form", KGENOME_NUCLEO_REQUEST },
		{ "Request.QueryString", KGENOME_NUCLEO_REQUEST },
		{ "Request.Params", KGENOME_NUCLEO_REQUEST },
		{ "Request.Files", KGENOME_NUCLEO_REQUEST },
		{ "Request.Cookies", KGENOME_NUCLEO_REQUEST },
		{ "Request.Item", KGENOME_NUCLEO_REQUEST },
		{ "Request.Headers", KGENOME_NUCLEO_REQUEST },
		{ "Request.InputStream", KGENOME_NUCLEO_REQUEST },
		{ "Request.BinaryRead", KGENOME_NUCLEO_REQUEST },
		{ "Process.Start", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "ProcessStartInfo", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "File.ReadAllText", KGENOME_NUCLEO_FILE_OPEN },
		{ "File.ReadAllBytes", KGENOME_NUCLEO_FILE_OPEN },
		{ "File.ReadAllLines", KGENOME_NUCLEO_FILE_OPEN },
		{ "File.OpenRead", KGENOME_NUCLEO_FILE_OPEN },
		{ "File.Open", KGENOME_NUCLEO_FILE_OPEN },
		{ "File.WriteAllText", KGENOME_NUCLEO_WRITE },
		{ "File.WriteAllBytes", KGENOME_NUCLEO_WRITE },
		{ "File.AppendAllText", KGENOME_NUCLEO_WRITE },
		{ "File.Create", KGENOME_NUCLEO_WRITE },
		{ "File.OpenWrite", KGENOME_NUCLEO_WRITE },
		{ "File.Copy", KGENOME_NUCLEO_WRITE },
		{ "FileInfo.CopyTo", KGENOME_NUCLEO_WRITE },
		{ "HttpPostedFile.SaveAs", KGENOME_NUCLEO_WRITE },
		{ "File.Delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "Directory.Delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "FileInfo.Delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "DirectoryInfo.Delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "File.Move", KGENOME_NUCLEO_FILE_RENAME },
		{ "Directory.Move", KGENOME_NUCLEO_FILE_RENAME },
		{ "FileInfo.MoveTo", KGENOME_NUCLEO_FILE_RENAME },
		{ "File.SetAttributes", KGENOME_NUCLEO_PERM_SET },
		{ "File.SetLastWriteTime", KGENOME_NUCLEO_TIMESTOMP },
		{ "File.SetCreationTime", KGENOME_NUCLEO_TIMESTOMP },
		{ "TcpClient", KGENOME_NUCLEO_NET_CONNECT },
		{ "Socket", KGENOME_NUCLEO_NET_CONNECT },
		{ "TcpListener", KGENOME_NUCLEO_NET_LISTEN },
		{ "UdpClient", KGENOME_NUCLEO_NET_OPEN },
		{ "WebClient", KGENOME_NUCLEO_HTTP_OPEN },
		{ "HttpClient", KGENOME_NUCLEO_HTTP_OPEN },
		{ "WebClient.DownloadString", KGENOME_NUCLEO_HTTP_FETCH },
		{ "WebClient.DownloadFile", KGENOME_NUCLEO_HTTP_FETCH },
		{ "WebClient.DownloadData", KGENOME_NUCLEO_HTTP_FETCH },
		{ "WebRequest.Create", KGENOME_NUCLEO_HTTP_FETCH },
		{ "HttpClient.GetAsync", KGENOME_NUCLEO_HTTP_FETCH },
		{ "HttpClient.GetStringAsync", KGENOME_NUCLEO_HTTP_FETCH },
		{ "WebClient.UploadString", KGENOME_NUCLEO_HTTP_SEND },
		{ "WebClient.UploadFile", KGENOME_NUCLEO_HTTP_SEND },
		{ "WebClient.UploadData", KGENOME_NUCLEO_HTTP_SEND },
		{ "HttpClient.PostAsync", KGENOME_NUCLEO_HTTP_SEND },
		{ "Dns.GetHostEntry", KGENOME_NUCLEO_DNS },
		{ "Dns.GetHostAddresses", KGENOME_NUCLEO_DNS },
		{ "Dns.GetHostByName", KGENOME_NUCLEO_DNS },
		{ "Dns.Resolve", KGENOME_NUCLEO_DNS },
		{ "Registry.SetValue", KGENOME_NUCLEO_REG_SET },
		{ "RegistryKey.SetValue", KGENOME_NUCLEO_REG_SET },
		{ "RegistryKey.CreateSubKey", KGENOME_NUCLEO_REG_SET },
		{ "RegistryKey.DeleteValue", KGENOME_NUCLEO_REG_SET },
	};
	/* kept out on purpose; files of 4840 benign / 6 malware that call it */
	static const struct nn_out out[] = {
		{ "Request", "335 / 0" },
		{ "Request.ServerVariables", "3 / 0" },
		{ "Request.UserAgent", "22 / 0" },
		{ "Server.MapPath", "1 / 0" },
		{ "File.Exists", "22 / 0" },
		{ "FileStream", "17 / 0" },
		{ "StreamReader", "25 / 4" },
		{ "StreamWriter", "14 / 0" },
		{ "Directory.GetFiles", "4 / 0" },
		{ "Thread.Sleep", "10 / 0" },
		{ "Encoding.UTF8.GetString", "4 / 0" },
		{ "Process.GetProcesses", "0 / 0" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"system",
		"fork",
		"chmod",
		"unlink",
		"popen",
		"execve",
		"mmap",
		"base64_decode",
		"CreateProcessA",
		"VirtualAlloc",
		"shell_exec",
		"Invoke-Expression",
		"WScript.Shell.Run",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"Assembly.Load",
		"CSharpCodeProvider.CompileAssemblyFromSource",
		"Process.Start",
		"ProcessStartInfo",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 7u },
		{ KGENOME_NUCLEO_CRYPTO, 6u },
		{ KGENOME_NUCLEO_EVAL, 3u },
		{ KGENOME_NUCLEO_CREATE, 7u },
		{ KGENOME_NUCLEO_DYNCALL, 4u },
		{ KGENOME_NUCLEO_DYNLOAD, 10u },
		{ KGENOME_NUCLEO_LIB_OPEN, 2u },
		{ KGENOME_NUCLEO_REQUEST, 9u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 2u },
		{ KGENOME_NUCLEO_FILE_OPEN, 5u },
		{ KGENOME_NUCLEO_WRITE, 8u },
		{ KGENOME_NUCLEO_FILE_DELETE, 4u },
		{ KGENOME_NUCLEO_FILE_RENAME, 3u },
		{ KGENOME_NUCLEO_PERM_SET, 1u },
		{ KGENOME_NUCLEO_TIMESTOMP, 2u },
		{ KGENOME_NUCLEO_NET_CONNECT, 2u },
		{ KGENOME_NUCLEO_NET_LISTEN, 1u },
		{ KGENOME_NUCLEO_NET_OPEN, 1u },
		{ KGENOME_NUCLEO_HTTP_OPEN, 2u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 6u },
		{ KGENOME_NUCLEO_HTTP_SEND, 4u },
		{ KGENOME_NUCLEO_DNS, 4u },
		{ KGENOME_NUCLEO_REG_SET, 4u },
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
	NN_CK(rows == 97u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 1, "Convert.FromBase64String");
	nn_check_stable(TARGET, "Convert.FromBase64String");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "Convert.FromBase64String") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_dotnet_names: the rows of the .NET table, in the case it keeps, and the names it keeps out");
}
