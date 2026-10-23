/*
 * nucleo_names_perl.c - what a Perl name means, in the vocabulary a native program's imports are read in.
 *
 * Perl's built-in functions are written bare ("system", "socket", "connect", "fork"); a module's function is written with
 * its module as the program writes it, with '.' where Perl writes `::` or `->` ("MIME.Base64.decode_base64",
 * "IO.Socket.INET.new", "POSIX.setsid"); and where a module exports a function that scripts then call bare, the bare name is
 * a row when it is as unambiguous as the qualified one ("decode_base64", "inet_aton", "getstore"). A key of %ENV that is a
 * request is spelled "ENV.QUERY_STRING". The back-quote and qx forms start a process but are not names: the lexer reads them
 * as strings (the evidence below does not see them either). Case matters (no `fold`).
 *
 * The evidence is the Perl of 31 malware files (IRC bots, shellbots, reverse shells and cgi shells; 21 families by the
 * tokens they share) against 2624 benign files (the system's modules and scripts). [Unverified: that is few malware files,
 * and the benign set is mostly library code; a row that neither set uses says so.]
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: decode_base64 is the step between where a payload is kept and where it runs (3/2624 benign, 1/31 malware; as a
	 * module function 2/2624 benign, 0/31 malware); uri_unescape is the percent decoding (7/2624 benign, 0/31 malware); the
	 * Compress::Zlib functions are the decompressors. pack and unpack are far too common to be rows (unpack 220/2624 benign,
	 * 5/31 malware, pack 79/2624 benign, 8/31 malware: they are how Perl reads any binary record), and so are reverse, chr and
	 * ord (below).
	 */
	{ .name = "decode_base64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "MIME.Base64.decode_base64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "uri_unescape", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "URI.Escape.uri_unescape", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "uncompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Compress.Zlib.uncompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "memGunzip", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Compress.Zlib.memGunzip", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * EVAL: the string form of eval runs text now (11 of the 31 malware files and 186 of the 2624 benign ones use it with an
	 * operand that is not a block); the block form `eval { ... }` is Perl's try (235 of the 2624 benign files and 7 of the 31
	 * malware ones) and is NOT this row: the reader tells them by the `{`. The name alone is 357/2624 benign, 13/31 malware,
	 * which is why the matcher, and not the name, is the evidence.
	 * DYNCALL: "(dynamic)" is `&$code(...)`, `&{$code}(...)`, `$obj->$method(...)` and `$class->$name`: a callee that is a value
	 * (the `&$` form is in 168/2624 benign files, which is why the row is the call of a value and not a claim by itself).
	 * DYNLOAD: "(load)" is `require $file` and `$class->new` with the class in a variable.
	 */
	{ .name = "eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * REQUEST: what the sender of a CGI request chose: the query string and the cookie of %ENV, the body from STDIN, and
	 * CGI.pm's param. [Unverified: QUERY_STRING is 0/2624 benign, 2/31 malware (the one CGI shell of the corpus reads it); the
	 * rest have no occurrence.]
	 */
	{ .name = "ENV.QUERY_STRING", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ENV.HTTP_COOKIE", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ENV.HTTP_USER_AGENT", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ENV.CONTENT_LENGTH", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "CGI.param", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: the native word is proc-start for every one of them. system 90/2624 benign, 15/31 malware and exec 31/2624
	 * benign, 4/31 malware are the shells and the bots' command runner; open3 and open2 run a command with its descriptors. fork
	 * makes a separate address space (13/2624 benign, 14/31 malware: the daemon of a bot), POSIX::setsid is what that daemon
	 * does to leave its terminal (2/2624 benign, 0/31 malware) and POSIX::dup2 points a standard descriptor at a socket.
	 * [Unverified: dup2 has no occurrence.]
	 */
	{ .name = "system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "readpipe", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "open3", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "open2", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "IPC.Open3.open3", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "IPC.Open2.open2", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "POSIX.setsid", .cap = KGENOME_NUCLEO_BACKGROUND },
	{ .name = "POSIX.dup2", .cap = KGENOME_NUCLEO_FD_REDIR },
	/*
	 * FILE: what a shell's file manager does: unlink 107/2624 benign, 1/31 malware, rename 38/2624 benign, 0/31 malware, chmod
	 * 44/2624 benign, 0/31 malware, chown, utime (the timestomp); File::Copy's copy and move, which scripts call bare (copy
	 * 37/2624 benign, 0/31 malware, move 6/2624 benign, 0/31 malware). [Unverified: copy and move have no malware occurrence.]
	 * open is far too common to be a row (below).
	 */
	{ .name = "unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "move", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "utime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "copy", .cap = KGENOME_NUCLEO_WRITE },
	/*
	 * NETWORK: the built-in socket functions, which are what the bots and the reverse shells here are made of: socket 7/2624
	 * benign, 12/31 malware, connect 10/2624 benign, 12/31 malware, send 15/2624 benign, 10/31 malware (the function;
	 * `$obj->send` is another name), bind, listen, accept, recv. inet_aton, inet_ntoa, sockaddr_in and pack_sockaddr_in build
	 * the address a native program builds with inet_addr and htons (inet_aton 6/2624 benign, 12/31 malware, sockaddr_in 6/2624
	 * benign, 12/31 malware). IO::Socket::INET->new connects when it is given PeerAddr (the form the bots here use, 10/2624
	 * benign, 10/31 malware) and listens when it is given Listen; the client is the one named. LWP, HTTP::Tiny and getstore are
	 * the HTTP layer (1/2624 benign, 4/31 malware); Net::FTP and Net::Telnet connect. DNS: gethostbyname 15/2624 benign, 3/31
	 * malware, gethostbyaddr, getaddrinfo and Net::DNS.
	 */
	{ .name = "socket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "IO.Socket.INET.new", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Net.FTP.new", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "Net.Telnet.new", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "recv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "send", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "inet_aton", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_ntoa", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "sockaddr_in", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "pack_sockaddr_in", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "LWP.UserAgent.new", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "HTTP.Tiny.new", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "LWP.Simple.get", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "LWP.Simple.getstore", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "getstore", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "gethostbyaddr", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Socket.getaddrinfo", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "Net.DNS.Resolver.new", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * LEFT OUT, because the name is not the evidence, with the file counts of the 31 malware / 2624 benign files: open 317/2624
	 * benign, 20/31 malware and close 314/2624 benign, 19/31 malware, print 530/2624 benign, 28/31 malware (every program),
	 * opendir 40/2624 benign, 1/31 malware, readdir, mkdir 47/2624 benign, 0/31 malware, glob 34/2624 benign, 0/31 malware, stat
	 * 68/2624 benign, 5/31 malware; pack 79/2624 benign, 8/31 malware, unpack 220/2624 benign, 5/31 malware, reverse 58/2624
	 * benign, 0/31 malware, chr 50/2624 benign, 2/31 malware, ord 60/2624 benign, 1/31 malware, hex, oct, sprintf; sleep 71/2624
	 * benign, 14/31 malware (a wait is how every poll loop works, and no table of this set names a wait), alarm 8/2624 benign,
	 * 5/31 malware, select, time, srand 37/2624 benign, 2/31 malware, rand, exit 134/2624 benign, 20/31 malware, local 428/2624
	 * benign, 12/31 malware; kill 15/2624 benign, 1/31 malware, waitpid 14/2624 benign, 11/31 malware (no word for killing a
	 * process); require 791/2624 benign, 9/31 malware, use 1412/2624 benign, 24/31 malware, do 158/2624 benign, 6/31 malware
	 * (the language's own loading: require is in 30% of the benign files and use in 54%); sub, ref 403/2624 benign, 1/31
	 * malware, can 22/2624 benign, 0/31 malware; shutdown 4/2624 benign, 7/31 malware, crypt 2/2624 benign, 1/31 malware (a
	 * password hash: no word); getpwuid, getlogin, hostname, umask, chdir, syscall. NOT NAMED because the vocabulary has no word
	 * for it, and it is a line of the malware here: assigning to $0 renames the process in the process list (12 of the 31
	 * malware files and 8 of the 2624 benign ones assign it), which is not a name and so not a row - the wiring has to see an
	 * assignment to the variable.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_perl = {
	.target = KGENOME_NUCLEO_T_PERL, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
