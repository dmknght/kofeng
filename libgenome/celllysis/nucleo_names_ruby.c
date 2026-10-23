/*
 * nucleo_names_ruby.c - what a Ruby name means, in the vocabulary a native program's imports are read in.
 *
 * A class or module method is written with its class as the program writes it, with '.' where Ruby writes `::` or `.`
 * ("Base64.decode64", "Net.HTTP.get", "Open3.capture3", "File.delete"); the Kernel functions are written bare ("system",
 * "exec", "eval", "send") and `Kernel.system` is the same row spelled with its module. A request member is written with the
 * object the handler names it by ("request.params", "params"). Case matters (no `fold`).
 *
 * THE EVIDENCE IS NOT MALWARE, and the table says so rather than counting it as such: this machine holds no Ruby malware (no
 * .rb file in the sample sets, nothing of the Bazaar set that is Ruby source). The comparison used is 5211 files of the
 * Metasploit framework - exploit modules, tools and scripts, the Ruby that offensive tooling is written in, counted below as
 * "Metasploit" - against 338 benign files (the bundler, rake, webrick and the other gems installed with the language). A
 * name is a row when it is the language's own API for the act, is rare in the gems, and the framework's own helpers
 * (print_status, send_request_cgi, cmd_exec) do not hide it; most of the counts for Metasploit are low because the framework
 * wraps the standard library. Every row is therefore [Unverified] against malware and is the documented API.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: Base64.decode64 and its strict and url-safe forms (0/338 benign, 16/5211 Metasploit), Zlib's inflate and gunzip
	 * (0/338 benign, 1/5211 Metasploit), CGI.unescape and URI's percent decoders. unpack is the Ruby way to read any binary
	 * record (4/338 benign, 251/5211 Metasploit, as a member of anything) and is not a row.
	 */
	{ .name = "Base64.decode64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Base64.strict_decode64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Base64.urlsafe_decode64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Zlib.inflate", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Zlib.Inflate.inflate", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Zlib.gunzip", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Zlib.GzipReader.new", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "CGI.unescape", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "URI.decode_www_form_component", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "URI.decode", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * EVAL: eval and the three evals of a class or an object that take a string - eval 3/338 benign, 2/5211 Metasploit,
	 * instance_eval 6/338 benign, 0/5211 Metasploit, class_eval 5/338 benign, 1/5211 Metasploit, module_eval 3/338 benign,
	 * 0/5211 Metasploit. Each of them has a block form that is metaprogramming and is not this row; the reader tells them by
	 * what follows the name. DYNCALL: send, public_send and __send__ call the method whose NAME they are given (send 7/338
	 * benign, 30/5211 Metasploit, public_send 1/338 benign, 1/5211 Metasploit); the row "(dynamic)" is a call of a value
	 * (`m.call`, `obj.method(name).call`). DYNLOAD: const_get makes a class out of a name; Marshal and YAML instantiate what
	 * their data says, as PHP's unserialize does (YAML.load is YAML.unsafe_load in older Rubies); the row "(load)" is
	 * `Object.const_get(x)` and `x.constantize` with x not a literal.
	 */
	{ .name = "eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "Kernel.eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "instance_eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "class_eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "module_eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "send", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "public_send", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "__send__", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "const_get", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Object.const_get", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Marshal.load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Marshal.restore", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "YAML.load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "YAML.unsafe_load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Psych.load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = "Psych.unsafe_load", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: `load file` runs another file, as PHP's include does (7/338 benign, 3/5211 Metasploit); Fiddle is Ruby's libffi,
	 * with which a native library is opened (1/338 benign, 2/5211 Metasploit), and DL is its older name. require and
	 * require_relative are in most Ruby files (106/338 benign, 698/5211 Metasploit, 129/338 benign, 0/5211 Metasploit) and are
	 * the language's own import: not rows.
	 */
	{ .name = "load", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "Fiddle.dlopen", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "DL.dlopen", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender of an HTTP request chose, in the objects of Rack, Rails and Sinatra, and CGI's own. [Unverified:
	 * params 1/338 benign, 49/5211 Metasploit is the only one with an occurrence in either set.]
	 */
	{ .name = "params", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.params", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.body", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "request.cookies", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "CGI.new", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. system 7/338 benign, 7/5211 Metasploit, exec 3/338 benign,
	 * 74/5211 Metasploit, spawn, IO.popen 3/338 benign, 2/5211 Metasploit, the Open3 family (1/338 benign, 3/5211 Metasploit)
	 * and PTY.spawn. fork 2/338 benign, 1/5211 Metasploit, Process.setsid and Process.daemon are what a daemon does to leave its
	 * terminal (BACKGROUND), as in the Perl and Python tables.
	 */
	{ .name = "system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Kernel.system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Kernel.exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Kernel.spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Process.spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "IO.popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Open3.capture2", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Open3.capture2e", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Open3.capture3", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Open3.popen2", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "Open3.popen3", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "PTY.spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "Process.fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "Process.setsid", .cap = KGENOME_NUCLEO_BACKGROUND },
	{ .name = "Process.daemon", .cap = KGENOME_NUCLEO_BACKGROUND },
	/*
	 * FILE: what a file manager does: File.delete 2/338 benign, 15/5211 Metasploit, FileUtils.rm_rf 9/338 benign, 2/5211
	 * Metasploit, rename and mv, chmod and chown, utime (the timestomp), File.write and binwrite, FileUtils.cp. File.open 28/338
	 * benign, 244/5211 Metasploit and File.read 10/338 benign, 108/5211 Metasploit are far too common to be rows.
	 */
	{ .name = "File.delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "File.unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "FileUtils.rm", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "FileUtils.rm_r", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "FileUtils.rm_rf", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "FileUtils.remove_entry", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "File.rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "FileUtils.mv", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "File.chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "FileUtils.chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "File.chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "FileUtils.chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "File.utime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "File.write", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "File.binwrite", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "FileUtils.cp", .cap = KGENOME_NUCLEO_WRITE },
	/*
	 * NETWORK: the socket classes of the standard library and Net::HTTP, with the same words as the other tables: TCPSocket
	 * connects when it is made (1/338 benign, 1/5211 Metasploit), TCPServer listens, UDPSocket and Socket.new open;
	 * Net::HTTP.get, get_response and post fetch in one call, Net::HTTP.start connects, Net::HTTP.new makes the client (1/338
	 * benign, 5/5211 Metasploit); URI.open is open-uri; Net::FTP, Net::Telnet and Net::SSH connect (0/338 benign, 36/5211
	 * Metasploit). DNS: Resolv and the socket lookups. [Unverified: against malware; Net::SSH.start is the brute-forcer of the
	 * framework.]
	 */
	{ .name = "UDPSocket.new", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "Socket.new", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "TCPSocket.new", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "TCPSocket.open", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Socket.tcp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Net.FTP.new", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Net.Telnet.new", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Net.SSH.start", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "TCPServer.new", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "Net.HTTP.new", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "Net.HTTP.start", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "Net.HTTP.get", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Net.HTTP.get_response", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Net.HTTP.post", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "URI.open", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "Resolv.getaddress", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Resolv.getaddresses", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Resolv.getname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Socket.gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "IPSocket.getaddress", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Resolv.DNS.new", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 5211 Metasploit / 338 benign files: File.open,
	 * File.read, File.binread 2/338 benign, 66/5211 Metasploit, File.readlines, IO.read, Dir.glob, Dir.entries, Dir.mkdir,
	 * FileUtils.mkdir_p 17/338 benign, 27/5211 Metasploit, File.symlink, FileUtils.touch (every program); require,
	 * require_relative, autoload 17/338 benign, 0/5211 Metasploit; ENV 33/338 benign, 33/5211 Metasploit, ARGV 7/338 benign,
	 * 34/5211 Metasploit, gets, $stdin (the environment and the command line are not a request); sleep 2/338 benign, 179/5211
	 * Metasploit, exit, abort, at_exit, trap, rand, srand; proc 13/338 benign, 83/5211 Metasploit, lambda 9/338 benign, 57/5211
	 * Metasploit, Proc.new, define_method, Class.new 4/338 benign, 1/5211 Metasploit, Module.new, instance_exec (blocks and
	 * metaprogramming: the language), method 13/338 benign, 154/5211 Metasploit, instance_variable_get; pack and unpack,
	 * reverse; open 3/338 benign, 11/5211 Metasploit (Kernel#open runs a command when its argument starts with a pipe: that is
	 * the argument); ERB.new 2/338 benign, 9/5211 Metasploit (a template is compiled to Ruby, in a web framework's every view).
	 * NOT NAMED because the vocabulary has no word: creating a directory or a link, and the framework's own session and payload
	 * objects.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_ruby = {
	.target = KGENOME_NUCLEO_T_RUBY, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
