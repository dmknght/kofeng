/*
 * nucleo_names_py.c - what a Python name means, in the vocabulary a native program's imports are read in.
 *
 * A module function is written with its module as the program writes it ("os.system", "subprocess.Popen",
 * "base64.b64decode"), and the Python 2 spelling is a row of its own where it differs ("urllib2.urlopen",
 * "commands.getoutput"); the bare name after `from base64 import b64decode` is a row only where the bare name is as
 * unambiguous as the qualified one ("b64decode", "eval", "exec", "compile", "__import__"). A method of an object the program
 * holds in a variable is written with the CLASS of the object, so `s.connect(addr)` after `s = socket.socket(...)` is
 * "socket.socket.connect"; an object that carries no class a reader can find is not a row. Case matters (no `fold`).
 *
 * The evidence is the Python of 42 malware files (bots, reverse shells and ransomware scripts; 21 families by the tokens
 * they share - this machine holds very little Python malware: of the 243 Python-named entries of the Bazaar sample set 242
 * are Windows executables, not source) against 1695 benign files (the standard library, installed packages, tools).
 * [Unverified: with that few malware files most rows rest on the benign counts being small and on the documented API; the
 * rows that no file here uses say so.]
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: bytes made out of other bytes, with no key. base64.b64decode is 1/1695 benign, 9/42 malware (and the bare
	 * b64decode of a from-import is 1/1695 benign, 0/42 malware); the other base64 decoders, binascii's, bytes.fromhex and the
	 * decompressors are the same step with a different alphabet. unquote is the percent decoding (urllib.parse.unquote 9/1695
	 * benign, 0/42 malware). codecs.decode(x, "rot13") or "hex" is the form that names the codec in a string: 1/1695 benign,
	 * 0/42 malware.
	 */
	{ .name = "base64.b64decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.b32decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.b16decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.urlsafe_b64decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.decodebytes", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.decodestring", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "b64decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "binascii.unhexlify", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "binascii.a2b_base64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.decompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.decompressobj", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "gzip.decompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "bz2.decompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "codecs.decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "urllib.parse.unquote", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "urllib.unquote", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * With a key: AES.new of PyCryptodome is the cipher of the ransomware scripts here (0/1695 benign, 0/42 malware).
	 */
	{ .name = "AES.new", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * EVAL: text run as code, now. eval is 14/1695 benign, 0/42 malware and exec 33/1695 benign, 1/42 malware; execfile is the
	 * Python 2 one. A literal and a value are the same name here, and the argument is the matcher's: a program that evals a
	 * constant is not the program that evals what it decoded. CREATE: text that becomes a function or a code object, called
	 * later: compile (43/1695 benign, 0/42 malware; re.compile is a different name and is not this row) and the types that build
	 * one from a code object.
	 */
	{ .name = "eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "exec", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "execfile", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "compile", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "types.FunctionType", .cap = KGENOME_NUCLEO_CREATE },
	{ .name = "types.CodeType", .cap = KGENOME_NUCLEO_CREATE },
	/*
	 * DYNCALL: operator.methodcaller(name)(obj) is a call by a string; the row "(dynamic)" is a call of a value,
	 * `globals()[name]()`, `getattr(o, name)()` and a call of a variable the program did not write as a name. getattr alone is
	 * not a row: it is in 324/1695 benign, 0/42 malware.
	 * DYNLOAD: a module or an object named by a value. __import__ (52/1695 benign, 0/42 malware) and importlib.import_module
	 * (20/1695 benign, 0/42 malware) take the module's name; pickle and marshal instantiate whatever their data names, as PHP's
	 * unserialize does (pickle.loads 2/1695 benign, 0/42 malware, marshal.loads 3/1695 benign, 0/42 malware); imp's loaders are
	 * the Python 2 ones. The row "(load)" is `__import__(x)` and `import_module(x)` with x not a literal.
	 */
	{ .name = "operator.methodcaller", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "__import__", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "importlib.import_module", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "import_module", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "importlib.util.spec_from_file_location", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "imp.load_source", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "pickle.loads", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "pickle.load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "cPickle.loads", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "marshal.loads", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "marshal.load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: a native library loaded by ctypes (3/1695 benign, 0/42 malware); the Win32 calls made through
	 * ctypes.windll.kernel32.X are the PE table's names, X. [Unverified: no malware file here loads a library.]
	 */
	{ .name = "ctypes.CDLL", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "ctypes.cdll.LoadLibrary", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "ctypes.WinDLL", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender chose, in the request object of the web frameworks as the handlers name it (Flask's request.args
	 * and request.form; Django's request.GET and request.POST) and CGI's FieldStorage. [Unverified: neither set here is a web
	 * application; request.data is 2/1695 benign, 0/42 malware and request.body 3/1695 benign, 0/42 malware in the benign
	 * files.]
	 */
	{ .name = "request.args", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.form", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.values", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.cookies", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.files", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.get_json", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.data", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.GET", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.POST", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.FILES", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.COOKIES", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.body", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "cgi.FieldStorage", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. os.system 3/1695 benign, 0/42 malware, subprocess.call
	 * 11/1695 benign, 26/42 malware (the call of the bots here), subprocess.Popen 24/1695 benign, 0/42 malware, and the exec and
	 * spawn families, os.popen, commands.getoutput, pty.spawn (the upgrade of a reverse shell to a terminal), and os.startfile,
	 * which is ShellExecute. os.fork makes a separate address space (5/1695 benign, 1/42 malware); os.setsid (2/1695 benign,
	 * 0/42 malware) is what a daemon does to leave its terminal; os.dup2 points a standard descriptor at a socket, the line
	 * between a connect and a shell (4/1695 benign, 1/42 malware); os.mkfifo makes a named pipe (2/1695 benign, 0/42 malware).
	 */
	{ .name = "os.system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.execl", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.execlp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.execv", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.execve", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.execvp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.spawnl", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.spawnlp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.spawnv", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.spawnvp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.posix_spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.startfile", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "subprocess.call", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "subprocess.check_call", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "subprocess.check_output", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "subprocess.run", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "subprocess.Popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "subprocess.getoutput", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "commands.getoutput", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "pty.spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "os.fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "os.forkpty", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "os.setsid", .cap = KGENOME_NUCLEO_BACKGROUND },
	{ .name = "os.dup2", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "os.mkfifo", .cap = KGENOME_NUCLEO_PIPE },
	/*
	 * FILE: what a shell's file manager does and what a dropper does to its file: remove (44/1695 benign, 1/42 malware: one
	 * benign file in forty, which is why a node here is not a claim by itself and the rows are for the join with a decode or a
	 * download), rename, change the mode, set the times (os.utime, the timestomp), copy. open() itself is far too common to be a
	 * row (below).
	 */
	{ .name = "os.remove", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "os.unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "os.rmdir", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "os.removedirs", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "shutil.rmtree", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "os.rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "os.replace", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "shutil.move", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "os.chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "os.chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "os.utime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "shutil.copy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "shutil.copyfile", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "shutil.copy2", .cap = KGENOME_NUCLEO_WRITE },
	/*
	 * NETWORK: socket.socket opens one (17/1695 benign, 5/42 malware), create_connection connects; the methods are the class's
	 * (connect 16/1695 benign, 3/42 malware, bind, listen, accept, recv, send, sendall, sendto, as members of anything; the
	 * class is what makes them rows). The servers of the standard library bind and listen when they are constructed. urllib,
	 * urllib2 and requests fetch in one call (urllib.urlopen 0/1695 benign, 12/42 malware is the Python 2 downloader of the bots
	 * here); http.client opens a connection; ftplib, telnetlib and smtplib connect when they are given a host. DNS: the socket
	 * module's lookups.
	 */
	{ .name = "socket.socket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "socket.create_connection", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "socket.socket.connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ftplib.FTP", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ftplib.FTP_TLS", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "telnetlib.Telnet", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "smtplib.SMTP", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "smtplib.SMTP_SSL", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "socket.socket.bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "socket.socket.listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "socketserver.TCPServer", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "SocketServer.TCPServer", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "http.server.HTTPServer", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "BaseHTTPServer.HTTPServer", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "socket.socket.accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "socket.socket.recv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "socket.socket.recvfrom", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "socket.socket.send", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "socket.socket.sendall", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "socket.socket.sendto", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "urllib.request.urlopen", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "urllib.request.urlretrieve", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "urllib2.urlopen", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "urllib.urlopen", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "urllib.urlretrieve", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "requests.get", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "requests.post", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "requests.put", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "requests.request", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "http.client.HTTPConnection", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "http.client.HTTPSConnection", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "httplib.HTTPConnection", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "httplib.HTTPSConnection", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "socket.gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "socket.gethostbyaddr", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "socket.getaddrinfo", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * WINDOWS, from Python: the registry key and value of the persistence scripts. [Unverified: none occurs in either set
	 * (0/1695 benign, 0/42 malware).]
	 */
	{ .name = "winreg.SetValueEx", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "_winreg.SetValueEx", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "winreg.OpenKey", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "_winreg.OpenKey", .cap = KGENOME_NUCLEO_REG_OPEN },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 42 malware / 1695 benign files: open 289/1695
	 * benign, 6/42 malware and os.open, io.open (every program), getattr 324/1695 benign, 0/42 malware, setattr 101/1695 benign,
	 * 0/42 malware, globals 55/1695 benign, 0/42 malware, vars 55/1695 benign, 0/42 malware, functools.partial 46/1695 benign,
	 * 0/42 malware; os.environ 86/1695 benign, 0/42 malware, os.getenv, sys.argv 70/1695 benign, 18/42 malware, sys.stdin, input
	 * 137/1695 benign, 4/42 malware and raw_input 4/1695 benign, 25/42 malware (the command line and the terminal are not a
	 * request: raw_input is the prompt of most of the Python 2 malware scripts here and of a few benign ones, and a prompt is
	 * not the sender of a request); os.listdir 60/1695 benign, 0/42 malware, os.walk, glob.glob, os.makedirs 49/1695 benign,
	 * 1/42 malware, os.mkdir, os.symlink, os.getcwd, os.chdir, tempfile; time.sleep 20/1695 benign, 7/42 malware (about one
	 * benign file in eighty and in one malware script in six: a wait is how every poll loop works, and no table of this set
	 * names a wait); sys.exit, threading.Thread, signal.signal, atexit.register, platform.system, getpass.getuser,
	 * socket.gethostname (host identity), hashlib, struct.pack, base64.b64encode 3/1695 benign, 0/42 malware (an encode is not a
	 * decode), json, re.compile. NOT NAMED because the vocabulary has no word: creating a directory and a symbolic link, and a
	 * Windows call through ctypes.windll (read it as the PE name after the dll, not as a Python name).
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_py = {
	.target = KGENOME_NUCLEO_T_PY, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
