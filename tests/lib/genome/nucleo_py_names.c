/*
 * nucleo_py_names - the rows of the Python table, and the names it keeps out (libgenome/celllysis/nucleo_names_py.c): every row
 * resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row moved to
 * another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and the names
 * of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every Python program there is. Each is pinned here with the
 * file count that decided it - in the 1695 benign / 42 malware files the table was measured on (the measurement and its limits
 * are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_PY

int main(void)
{
	static const struct nn_is is[] = {
		{ "base64.b64decode", KGENOME_NUCLEO_DECODE },
		{ "base64.b32decode", KGENOME_NUCLEO_DECODE },
		{ "base64.b16decode", KGENOME_NUCLEO_DECODE },
		{ "base64.urlsafe_b64decode", KGENOME_NUCLEO_DECODE },
		{ "base64.decodebytes", KGENOME_NUCLEO_DECODE },
		{ "base64.decodestring", KGENOME_NUCLEO_DECODE },
		{ "b64decode", KGENOME_NUCLEO_DECODE },
		{ "binascii.unhexlify", KGENOME_NUCLEO_DECODE },
		{ "binascii.a2b_base64", KGENOME_NUCLEO_DECODE },
		{ "zlib.decompress", KGENOME_NUCLEO_DECODE },
		{ "zlib.decompressobj", KGENOME_NUCLEO_DECODE },
		{ "gzip.decompress", KGENOME_NUCLEO_DECODE },
		{ "bz2.decompress", KGENOME_NUCLEO_DECODE },
		{ "codecs.decode", KGENOME_NUCLEO_DECODE },
		{ "urllib.parse.unquote", KGENOME_NUCLEO_DECODE },
		{ "urllib.unquote", KGENOME_NUCLEO_DECODE },
		{ "AES.new", KGENOME_NUCLEO_CRYPTO },
		{ "eval", KGENOME_NUCLEO_EVAL },
		{ "exec", KGENOME_NUCLEO_EVAL },
		{ "execfile", KGENOME_NUCLEO_EVAL },
		{ "compile", KGENOME_NUCLEO_CREATE },
		{ "types.FunctionType", KGENOME_NUCLEO_CREATE },
		{ "types.CodeType", KGENOME_NUCLEO_CREATE },
		{ "operator.methodcaller", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "__import__", KGENOME_NUCLEO_DYNLOAD },
		{ "importlib.import_module", KGENOME_NUCLEO_DYNLOAD },
		{ "import_module", KGENOME_NUCLEO_DYNLOAD },
		{ "importlib.util.spec_from_file_location", KGENOME_NUCLEO_DYNLOAD },
		{ "imp.load_source", KGENOME_NUCLEO_DYNLOAD },
		{ "pickle.loads", KGENOME_NUCLEO_DYNLOAD },
		{ "pickle.load", KGENOME_NUCLEO_DYNLOAD },
		{ "cPickle.loads", KGENOME_NUCLEO_DYNLOAD },
		{ "marshal.loads", KGENOME_NUCLEO_DYNLOAD },
		{ "marshal.load", KGENOME_NUCLEO_DYNLOAD },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "ctypes.CDLL", KGENOME_NUCLEO_LIB_OPEN },
		{ "ctypes.cdll.LoadLibrary", KGENOME_NUCLEO_LIB_OPEN },
		{ "ctypes.WinDLL", KGENOME_NUCLEO_LIB_OPEN },
		{ "request.args", KGENOME_NUCLEO_REQUEST },
		{ "request.form", KGENOME_NUCLEO_REQUEST },
		{ "request.values", KGENOME_NUCLEO_REQUEST },
		{ "request.cookies", KGENOME_NUCLEO_REQUEST },
		{ "request.files", KGENOME_NUCLEO_REQUEST },
		{ "request.get_json", KGENOME_NUCLEO_REQUEST },
		{ "request.data", KGENOME_NUCLEO_REQUEST },
		{ "request.GET", KGENOME_NUCLEO_REQUEST },
		{ "request.POST", KGENOME_NUCLEO_REQUEST },
		{ "request.FILES", KGENOME_NUCLEO_REQUEST },
		{ "request.COOKIES", KGENOME_NUCLEO_REQUEST },
		{ "request.body", KGENOME_NUCLEO_REQUEST },
		{ "cgi.FieldStorage", KGENOME_NUCLEO_REQUEST },
		{ "os.system", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.popen", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.execl", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.execlp", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.execv", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.execve", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.execvp", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.spawnl", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.spawnlp", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.spawnv", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.spawnvp", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.posix_spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.startfile", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "subprocess.call", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "subprocess.check_call", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "subprocess.check_output", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "subprocess.run", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "subprocess.Popen", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "subprocess.getoutput", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "commands.getoutput", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "pty.spawn", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "os.fork", KGENOME_NUCLEO_SPAWN },
		{ "os.forkpty", KGENOME_NUCLEO_SPAWN },
		{ "os.setsid", KGENOME_NUCLEO_BACKGROUND },
		{ "os.dup2", KGENOME_NUCLEO_FD_REDIR },
		{ "os.mkfifo", KGENOME_NUCLEO_PIPE },
		{ "os.remove", KGENOME_NUCLEO_FILE_DELETE },
		{ "os.unlink", KGENOME_NUCLEO_FILE_DELETE },
		{ "os.rmdir", KGENOME_NUCLEO_FILE_DELETE },
		{ "os.removedirs", KGENOME_NUCLEO_FILE_DELETE },
		{ "shutil.rmtree", KGENOME_NUCLEO_FILE_DELETE },
		{ "os.rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "os.replace", KGENOME_NUCLEO_FILE_RENAME },
		{ "shutil.move", KGENOME_NUCLEO_FILE_RENAME },
		{ "os.chmod", KGENOME_NUCLEO_PERM_SET },
		{ "os.chown", KGENOME_NUCLEO_PERM_SET },
		{ "os.utime", KGENOME_NUCLEO_TIMESTOMP },
		{ "shutil.copy", KGENOME_NUCLEO_WRITE },
		{ "shutil.copyfile", KGENOME_NUCLEO_WRITE },
		{ "shutil.copy2", KGENOME_NUCLEO_WRITE },
		{ "socket.socket", KGENOME_NUCLEO_NET_OPEN },
		{ "socket.create_connection", KGENOME_NUCLEO_NET_CONNECT },
		{ "socket.socket.connect", KGENOME_NUCLEO_NET_CONNECT },
		{ "ftplib.FTP", KGENOME_NUCLEO_NET_CONNECT },
		{ "ftplib.FTP_TLS", KGENOME_NUCLEO_NET_CONNECT },
		{ "telnetlib.Telnet", KGENOME_NUCLEO_NET_CONNECT },
		{ "smtplib.SMTP", KGENOME_NUCLEO_NET_CONNECT },
		{ "smtplib.SMTP_SSL", KGENOME_NUCLEO_NET_CONNECT },
		{ "socket.socket.bind", KGENOME_NUCLEO_NET_BIND },
		{ "socket.socket.listen", KGENOME_NUCLEO_NET_LISTEN },
		{ "socketserver.TCPServer", KGENOME_NUCLEO_NET_LISTEN },
		{ "SocketServer.TCPServer", KGENOME_NUCLEO_NET_LISTEN },
		{ "http.server.HTTPServer", KGENOME_NUCLEO_NET_LISTEN },
		{ "BaseHTTPServer.HTTPServer", KGENOME_NUCLEO_NET_LISTEN },
		{ "socket.socket.accept", KGENOME_NUCLEO_NET_ACCEPT },
		{ "socket.socket.recv", KGENOME_NUCLEO_NET_READ },
		{ "socket.socket.recvfrom", KGENOME_NUCLEO_NET_READ },
		{ "socket.socket.send", KGENOME_NUCLEO_NET_WRITE },
		{ "socket.socket.sendall", KGENOME_NUCLEO_NET_WRITE },
		{ "socket.socket.sendto", KGENOME_NUCLEO_NET_WRITE },
		{ "urllib.request.urlopen", KGENOME_NUCLEO_HTTP_FETCH },
		{ "urllib.request.urlretrieve", KGENOME_NUCLEO_HTTP_FETCH },
		{ "urllib2.urlopen", KGENOME_NUCLEO_HTTP_FETCH },
		{ "urllib.urlopen", KGENOME_NUCLEO_HTTP_FETCH },
		{ "urllib.urlretrieve", KGENOME_NUCLEO_HTTP_FETCH },
		{ "requests.get", KGENOME_NUCLEO_HTTP_FETCH },
		{ "requests.post", KGENOME_NUCLEO_HTTP_FETCH },
		{ "requests.put", KGENOME_NUCLEO_HTTP_FETCH },
		{ "requests.request", KGENOME_NUCLEO_HTTP_FETCH },
		{ "http.client.HTTPConnection", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "http.client.HTTPSConnection", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "httplib.HTTPConnection", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "httplib.HTTPSConnection", KGENOME_NUCLEO_HTTP_CONNECT },
		{ "socket.gethostbyname", KGENOME_NUCLEO_DNS },
		{ "socket.gethostbyaddr", KGENOME_NUCLEO_DNS },
		{ "socket.getaddrinfo", KGENOME_NUCLEO_DNS },
		{ "winreg.SetValueEx", KGENOME_NUCLEO_REG_SET },
		{ "_winreg.SetValueEx", KGENOME_NUCLEO_REG_SET },
		{ "winreg.OpenKey", KGENOME_NUCLEO_REG_OPEN },
		{ "_winreg.OpenKey", KGENOME_NUCLEO_REG_OPEN },
	};
	/* kept out on purpose; files of 1695 benign / 42 malware that call it */
	static const struct nn_out out[] = {
		{ "open", "289 / 6" },
		{ "getattr", "324 / 0" },
		{ "setattr", "101 / 0" },
		{ "globals", "55 / 0" },
		{ "vars", "55 / 0" },
		{ "functools.partial", "46 / 0" },
		{ "os.environ", "86 / 0" },
		{ "sys.argv", "70 / 18" },
		{ "input", "137 / 4" },
		{ "raw_input", "4 / 25" },
		{ "os.listdir", "60 / 0" },
		{ "os.makedirs", "49 / 1" },
		{ "time.sleep", "20 / 7" },
		{ "base64.b64encode", "3 / 0" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"system",
		"fork",
		"chmod",
		"unlink",
		"socket",
		"Runtime.exec",
		"shell_exec",
		"base64_decode",
		"CreateProcessA",
		"VirtualAlloc",
		"mmap",
		"child_process.exec",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"subprocess.Popen",
		"os.system",
		"socket.socket",
		"pickle.loads",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 16u },
		{ KGENOME_NUCLEO_CRYPTO, 1u },
		{ KGENOME_NUCLEO_EVAL, 3u },
		{ KGENOME_NUCLEO_CREATE, 3u },
		{ KGENOME_NUCLEO_DYNCALL, 2u },
		{ KGENOME_NUCLEO_DYNLOAD, 11u },
		{ KGENOME_NUCLEO_LIB_OPEN, 3u },
		{ KGENOME_NUCLEO_REQUEST, 13u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 21u },
		{ KGENOME_NUCLEO_SPAWN, 2u },
		{ KGENOME_NUCLEO_BACKGROUND, 1u },
		{ KGENOME_NUCLEO_FD_REDIR, 1u },
		{ KGENOME_NUCLEO_PIPE, 1u },
		{ KGENOME_NUCLEO_FILE_DELETE, 5u },
		{ KGENOME_NUCLEO_FILE_RENAME, 3u },
		{ KGENOME_NUCLEO_PERM_SET, 2u },
		{ KGENOME_NUCLEO_TIMESTOMP, 1u },
		{ KGENOME_NUCLEO_WRITE, 3u },
		{ KGENOME_NUCLEO_NET_OPEN, 1u },
		{ KGENOME_NUCLEO_NET_CONNECT, 7u },
		{ KGENOME_NUCLEO_NET_BIND, 1u },
		{ KGENOME_NUCLEO_NET_LISTEN, 5u },
		{ KGENOME_NUCLEO_NET_ACCEPT, 1u },
		{ KGENOME_NUCLEO_NET_READ, 2u },
		{ KGENOME_NUCLEO_NET_WRITE, 3u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 9u },
		{ KGENOME_NUCLEO_HTTP_CONNECT, 4u },
		{ KGENOME_NUCLEO_DNS, 3u },
		{ KGENOME_NUCLEO_REG_SET, 2u },
		{ KGENOME_NUCLEO_REG_OPEN, 2u },
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
	NN_CK(rows == 132u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "subprocess.Popen");
	nn_check_stable(TARGET, "subprocess.Popen");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "subprocess.Popen") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_py_names: the rows of the Python table, in the case it keeps, and the names it keeps out");
}
