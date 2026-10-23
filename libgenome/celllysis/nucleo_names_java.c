/*
 * nucleo_names_java.c - what a Java name means as a JSP page (or a servlet) runs it, in the vocabulary a native program's
 * imports are read in.
 *
 * A class's static method or constructor is written with the class as the program writes it ("Class.forName",
 * "Cipher.getInstance", "URL.openStream"), and a method of an object the program holds in a variable is written with the
 * CLASS of the object ("File.delete", "Method.invoke"). A call on the result of a factory call is written without the
 * factory: `Runtime.getRuntime().exec(c)` is "Runtime.exec" and `Base64.getDecoder().decode(s)` is "Base64.decode" - the
 * chain is the language's way to write a method of a class it has only one instance of. A constructor that does the act when
 * it is made (a Socket connects, a FileInputStream opens) is the class name alone. The implicit objects of a JSP page are
 * written as the page writes them ("request.getParameter"). Case matters (no `fold`).
 *
 * The evidence is the Java of 12 JSP shells of the corpus (cmd shells, a reverse shell, file managers and uploaders; the
 * lexer reads the Java of a page with the same spans as a class file) against 4989 benign Java files of this machine
 * (decompiled applications and servlet examples; [Unverified: they are mostly Android application code, so the counts of
 * reflection and IO calls are those of that code, not of a web application]). A benign count of 0 is "not seen"; a row
 * without a measured occurrence says so.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: base64 (Base64.decode of Java 8 2/4989 benign, 0/12 malware, commons-codec's Base64.decodeBase64, the old sun
	 * BASE64Decoder, DatatypeConverter), URLDecoder.decode (1/4989 benign, 1/12 malware), the zip streams that read compressed
	 * bytes (GZIPInputStream 2/4989 benign, 1/12 malware) and Hex.decodeHex. With a key: Cipher.getInstance (2/4989 benign, 0/12
	 * malware).
	 */
	{ .name = "Base64.decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Base64.decodeBase64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "BASE64Decoder.decodeBuffer", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "DatatypeConverter.parseBase64Binary", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "DatatypeConverter.parseHexBinary", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Hex.decodeHex", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "URLDecoder.decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "GZIPInputStream", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "InflaterInputStream", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Inflater.inflate", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Cipher.getInstance", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * EVAL: text run as code, now: the javax.script engine, Groovy and BeanShell, and OGNL, which is how the Struts expression
	 * injections run. CREATE: a class made out of bytes (defineClass of a class loader: 1/4989 benign, 0/12 malware). DYNCALL:
	 * Method.invoke calls the method whose Method object it has - and `invoke` alone is in 1420/4989 benign, 0/12 malware,
	 * because every proxy and every reflection helper has one, so only the class-qualified name is a row - and "(dynamic)" is a
	 * call of a value; there is no other way in Java. DYNLOAD: Class.forName makes a class out of a name (8/4989 benign, 0/12
	 * malware), loadClass and the URLClassLoader load one from a place, newInstance makes the object; the row "(load)" is
	 * `Class.forName(x)` with x not a literal.
	 */
	{ .name = "ScriptEngine.eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "GroovyShell.evaluate", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "Interpreter.eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "Ognl.getValue", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "ClassLoader.defineClass", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "defineClass", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "Unsafe.defineClass", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "Method.invoke", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "Class.forName", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "ClassLoader.loadClass", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "URLClassLoader", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Constructor.newInstance", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Class.newInstance", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: a native library opened by a name: System.load and System.loadLibrary. [Unverified: no occurrence.]
	 */
	{ .name = "System.load", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "System.loadLibrary", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender of the request chose, in the implicit `request` object of a page and in the members of a
	 * servlet's request. request.getParameter is 0/4989 benign, 10/12 malware; getInputStream is the body of an upload (0/4989
	 * benign, 3/12 malware). A servlet that names its request `req` is a row too (2/4989 benign, 0/12 malware: both in a benign
	 * file).
	 */
	{ .name = "request.getParameter", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getParameterValues", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getParameterMap", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getInputStream", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getReader", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getHeader", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getQueryString", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getCookies", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getPart", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.getParts", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "req.getParameter", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "req.getInputStream", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. Runtime.exec: the chain's first call is 15/4989 benign, 8/12
	 * malware (it is also how a program reads the memory it has, which is why the row is the exec of the chain and not
	 * getRuntime); ProcessBuilder starts a process when start() is called (2/4989 benign, 0/12 malware).
	 */
	{ .name = "Runtime.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ProcessBuilder.start", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * FILE: what the file managers and the uploaders of the shells do: open to read (FileInputStream 16/4989 benign, 2/12
	 * malware, FileReader, RandomAccessFile, Files.readAllBytes), open to write (FileOutputStream 12/4989 benign, 3/12 malware,
	 * FileWriter, Files.write, createNewFile), copy, delete, rename, change the mode, set the times. [Unverified: the deletes
	 * and renames are the documented API; the shells use File.delete and renameTo, which the lexer sees only as members.]
	 */
	{ .name = "FileInputStream", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "FileReader", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "RandomAccessFile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "Files.readAllBytes", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "FileOutputStream", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "FileWriter", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "Files.write", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "Files.copy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.createNewFile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "Files.delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "Files.deleteIfExists", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "File.renameTo", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "Files.move", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "File.setReadable", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "File.setWritable", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "File.setExecutable", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "Files.setPosixFilePermissions", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "File.setLastModified", .cap = KGENOME_NUCLEO_TIMESTOMP },
	/*
	 * NETWORK: a Socket connects when it is made (4/4989 benign, 2/12 malware: the reverse shell of the corpus), a ServerSocket
	 * listens, a DatagramSocket opens; URL.openStream fetches in one call and URL.openConnection names the endpoint;
	 * HttpClient.execute and HttpClient.send are the library clients. DNS: InetAddress's lookups (2/4989 benign, 0/12 malware).
	 */
	{ .name = "Socket", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "SocketChannel.open", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ServerSocket", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "DatagramSocket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "URL.openStream", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "HttpClient.execute", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "HttpClient.send", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "URL.openConnection", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "InetAddress.getByName", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "InetAddress.getAllByName", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 12 malware / 4989 benign files: invoke on its
	 * own 1420/4989 benign, 0/12 malware, getMethod 7/4989 benign, 0/12 malware, newInstance 28/4989 benign, 0/12 malware
	 * (reflection helpers: the class is the identity); File.listFiles 0/4989 benign, 0/12 malware, File.list, mkdirs, mkdir,
	 * File.exists, File.getName (probing and listing); Thread.sleep 2/4989 benign, 1/12 malware, System.getProperty 4/4989
	 * benign, 1/12 malware, System.getenv, System.exit; MessageDigest.getInstance 15/4989 benign, 0/12 malware (a hash);
	 * InetAddress.getLocalHost, getHostName (host identity); print, println and the rest of out (the page's output);
	 * StringBuffer and the other string classes. NOT NAMED because the vocabulary has no word: nothing in this language that the
	 * corpus used.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_java = {
	.target = KGENOME_NUCLEO_T_JAVA, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
