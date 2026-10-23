/*
 * nucleo_names_tcl.c - what a Tcl command means, in the vocabulary a native program's imports are read in.
 *
 * Tcl has no function calls, only commands, and its file, binary, zlib, interp and package commands are ENSEMBLES: `file
 * delete x` is the command `file` with the subcommand `delete`. A row is the command word, and for an ensemble the command
 * and its subcommand joined with '.' ("file.delete", "binary.decode", "interp.eval"); a procedure of a package is written
 * with the package ("http.geturl" is `http::geturl`, "ncgi.value" is `ncgi::value`). Case matters (no `fold`).
 *
 * THE EVIDENCE IS THE THINNEST OF ANY TABLE and the table says so: there is no Tcl malware on this machine and the only Tcl
 * is 125 benign files (Tk's and Tcl's own library). The lexer reads the body of a braced command as a string, so the counts
 * below see the commands at the top level of a file and not the ones inside a procedure: a count here is a lower bound. A
 * name is a row because it is the language's command for the act and does not occur in the benign set at a rate that would
 * make it noise. Every row is [Unverified] against malware.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: `binary decode base64` and hex (Tcl 8.6), zlib's inflate, decompress and gunzip, and tcllib's base64 and uuencode
	 * packages.
	 */
	{ .name = "binary.decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.inflate", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.decompress", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "zlib.gunzip", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "base64.decode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "uuencode.decode", .cap = KGENOME_NUCLEO_DECODE },
	/*
	 * EVAL: uplevel runs a script in the caller's frame (1/125 benign, no malware set) and interp eval in another interpreter;
	 * `eval` itself is not a row (below). DYNCALL: the row "(dynamic)" is `$cmd args` and `{*}$cmd`, a command whose name is a
	 * value, and interp invokehidden. DYNLOAD: the row "(load)" is `package require $name` with a variable.
	 */
	{ .name = "uplevel", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "interp.eval", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "interp.invokehidden", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: `load file` opens a native library into the interpreter (1/125 benign, no malware set). `source` runs another
	 * file and is in 9/125 benign, no malware set (Tk loads its own library with it): not a row.
	 */
	{ .name = "load", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender of a CGI request chose: tcllib's ncgi package, cgi.tcl's cgi_import and the query string of the
	 * environment.
	 */
	{ .name = "ncgi.value", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ncgi.input", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "ncgi.nvlist", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "cgi_import", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "env.QUERY_STRING", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: exec runs a program (0/125 benign, no malware set); it is how a Tcl script does anything outside the interpreter,
	 * and the arguments are the matcher's. FILE: delete, rename, copy and attributes of the file command (0/125 benign, no
	 * malware set); `file attributes` reads and writes permissions, and where it only reads, it is the weaker act. NETWORK:
	 * socket connects, or with -server listens (the argument decides; the client is the one named), http::geturl fetches.
	 */
	{ .name = "exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "file.delete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "file.rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "file.copy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "file.attributes", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "socket", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "http.geturl", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	/*
	 * LEFT OUT, because the name is not the evidence, with the top-level file counts of the 125 benign files: eval 78/125
	 * benign, no malware set (Tk's widgets are built with it: it is the language's own way to expand a command and is in about
	 * three files of five), proc 68/125 benign, no malware set, source 9/125 benign, no malware set, open, puts, gets, close,
	 * read, catch 3/125 benign, no malware set, info 5/125 benign, no malware set, after (the timer and the sleep: a wait is how
	 * every event loop works), clock, rename (renames a COMMAND, not a file), trace, exit, cd, pwd 4/125 benign, no malware set,
	 * file.mkdir and the other file subcommands that only probe (exists, size, join, dirname, tail, extension), glob,
	 * fconfigure, fileevent, vwait, string, list, lappend, foreach, env and argv. NOT NAMED because the vocabulary has no word:
	 * nothing in this language.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_tcl = {
	.target = KGENOME_NUCLEO_T_TCL, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
