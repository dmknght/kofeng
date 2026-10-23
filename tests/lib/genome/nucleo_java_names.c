/*
 * nucleo_java_names - the rows of the Java (JSP) table, and the names it keeps out (libgenome/celllysis/nucleo_names_java.c):
 * every row resolves to its capability and gives its own name back through its id, the capability of every row is counted (a
 * row moved to another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing,
 * and the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every Java (JSP) program there is. Each is pinned here with
 * the file count that decided it - in the 4989 benign / 12 malware files the table was measured on (the measurement and its
 * limits are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_JAVA

int main(void)
{
	static const struct nn_is is[] = {
		{ "Base64.decode", KGENOME_NUCLEO_DECODE },
		{ "Base64.decodeBase64", KGENOME_NUCLEO_DECODE },
		{ "BASE64Decoder.decodeBuffer", KGENOME_NUCLEO_DECODE },
		{ "DatatypeConverter.parseBase64Binary", KGENOME_NUCLEO_DECODE },
		{ "DatatypeConverter.parseHexBinary", KGENOME_NUCLEO_DECODE },
		{ "Hex.decodeHex", KGENOME_NUCLEO_DECODE },
		{ "URLDecoder.decode", KGENOME_NUCLEO_DECODE },
		{ "GZIPInputStream", KGENOME_NUCLEO_DECODE },
		{ "InflaterInputStream", KGENOME_NUCLEO_DECODE },
		{ "Inflater.inflate", KGENOME_NUCLEO_DECODE },
		{ "Cipher.getInstance", KGENOME_NUCLEO_CRYPTO },
		{ "ScriptEngine.eval", KGENOME_NUCLEO_EVAL },
		{ "GroovyShell.evaluate", KGENOME_NUCLEO_EVAL },
		{ "Interpreter.eval", KGENOME_NUCLEO_EVAL },
		{ "Ognl.getValue", KGENOME_NUCLEO_EVAL },
		{ "ClassLoader.defineClass", KGENOME_NUCLEO_CREATE },
		{ "defineClass", KGENOME_NUCLEO_CREATE },
		{ "Unsafe.defineClass", KGENOME_NUCLEO_CREATE },
		{ "Method.invoke", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "Class.forName", KGENOME_NUCLEO_DYNLOAD },
		{ "ClassLoader.loadClass", KGENOME_NUCLEO_DYNLOAD },
		{ "URLClassLoader", KGENOME_NUCLEO_DYNLOAD },
		{ "Constructor.newInstance", KGENOME_NUCLEO_DYNLOAD },
		{ "Class.newInstance", KGENOME_NUCLEO_DYNLOAD },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "System.load", KGENOME_NUCLEO_LIB_OPEN },
		{ "System.loadLibrary", KGENOME_NUCLEO_LIB_OPEN },
		{ "request.getParameter", KGENOME_NUCLEO_REQUEST },
		{ "request.getParameterValues", KGENOME_NUCLEO_REQUEST },
		{ "request.getParameterMap", KGENOME_NUCLEO_REQUEST },
		{ "request.getInputStream", KGENOME_NUCLEO_REQUEST },
		{ "request.getReader", KGENOME_NUCLEO_REQUEST },
		{ "request.getHeader", KGENOME_NUCLEO_REQUEST },
		{ "request.getQueryString", KGENOME_NUCLEO_REQUEST },
		{ "request.getCookies", KGENOME_NUCLEO_REQUEST },
		{ "request.getPart", KGENOME_NUCLEO_REQUEST },
		{ "request.getParts", KGENOME_NUCLEO_REQUEST },
		{ "req.getParameter", KGENOME_NUCLEO_REQUEST },
		{ "req.getInputStream", KGENOME_NUCLEO_REQUEST },
		{ "Runtime.exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "ProcessBuilder.start", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "FileInputStream", KGENOME_NUCLEO_FILE_OPEN },
		{ "FileReader", KGENOME_NUCLEO_FILE_OPEN },
		{ "RandomAccessFile", KGENOME_NUCLEO_FILE_OPEN },
		{ "Files.readAllBytes", KGENOME_NUCLEO_FILE_OPEN },
		{ "FileOutputStream", KGENOME_NUCLEO_WRITE },
		{ "FileWriter", KGENOME_NUCLEO_WRITE },
		{ "Files.write", KGENOME_NUCLEO_WRITE },
		{ "Files.copy", KGENOME_NUCLEO_WRITE },
		{ "File.createNewFile", KGENOME_NUCLEO_WRITE },
		{ "File.delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "Files.delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "Files.deleteIfExists", KGENOME_NUCLEO_FILE_DELETE },
		{ "File.renameTo", KGENOME_NUCLEO_FILE_RENAME },
		{ "Files.move", KGENOME_NUCLEO_FILE_RENAME },
		{ "File.setReadable", KGENOME_NUCLEO_PERM_SET },
		{ "File.setWritable", KGENOME_NUCLEO_PERM_SET },
		{ "File.setExecutable", KGENOME_NUCLEO_PERM_SET },
		{ "Files.setPosixFilePermissions", KGENOME_NUCLEO_PERM_SET },
		{ "File.setLastModified", KGENOME_NUCLEO_TIMESTOMP },
		{ "Socket", KGENOME_NUCLEO_NET_CONNECT },
		{ "SocketChannel.open", KGENOME_NUCLEO_NET_CONNECT },
		{ "ServerSocket", KGENOME_NUCLEO_NET_LISTEN },
		{ "DatagramSocket", KGENOME_NUCLEO_NET_OPEN },
		{ "URL.openStream", KGENOME_NUCLEO_HTTP_FETCH },
		{ "HttpClient.execute", KGENOME_NUCLEO_HTTP_FETCH },
		{ "HttpClient.send", KGENOME_NUCLEO_HTTP_FETCH },
		{ "URL.openConnection", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "InetAddress.getByName", KGENOME_NUCLEO_DNS },
		{ "InetAddress.getAllByName", KGENOME_NUCLEO_DNS },
	};
	/* kept out on purpose; files of 4989 benign / 12 malware that call it */
	static const struct nn_out out[] = {
		{ "invoke", "1420 / 0" },
		{ "getMethod", "7 / 0" },
		{ "newInstance", "28 / 0" },
		{ "File.listFiles", "0 / 0" },
		{ "Thread.sleep", "2 / 1" },
		{ "System.getProperty", "4 / 1" },
		{ "MessageDigest.getInstance", "15 / 0" },
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
		"os.system",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"Class.forName",
		"Runtime.exec",
		"ProcessBuilder.start",
		"Cipher.getInstance",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 10u },
		{ KGENOME_NUCLEO_CRYPTO, 1u },
		{ KGENOME_NUCLEO_EVAL, 4u },
		{ KGENOME_NUCLEO_CREATE, 3u },
		{ KGENOME_NUCLEO_DYNCALL, 2u },
		{ KGENOME_NUCLEO_DYNLOAD, 6u },
		{ KGENOME_NUCLEO_LIB_OPEN, 2u },
		{ KGENOME_NUCLEO_REQUEST, 12u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 2u },
		{ KGENOME_NUCLEO_FILE_OPEN, 4u },
		{ KGENOME_NUCLEO_WRITE, 5u },
		{ KGENOME_NUCLEO_FILE_DELETE, 3u },
		{ KGENOME_NUCLEO_FILE_RENAME, 2u },
		{ KGENOME_NUCLEO_PERM_SET, 4u },
		{ KGENOME_NUCLEO_TIMESTOMP, 1u },
		{ KGENOME_NUCLEO_NET_CONNECT, 2u },
		{ KGENOME_NUCLEO_NET_LISTEN, 1u },
		{ KGENOME_NUCLEO_NET_OPEN, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 3u },
		{ KGENOME_NUCLEO_HTTP_CONNECT, 1u },
		{ KGENOME_NUCLEO_DNS, 2u },
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
	NN_CK(rows == 71u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "Class.forName");
	nn_check_stable(TARGET, "Class.forName");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "Class.forName") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_java_names: the rows of the Java (JSP) table, in the case it keeps, and the names it keeps out");
}
