/*
 * nucleo_tcl_names - the rows of the Tcl table, and the names it keeps out (libgenome/celllysis/nucleo_names_tcl.c): every row
 * resolves to its capability and gives its own name back through its id, the capability of every row is counted (a row moved to
 * another word, added or dropped changes a count), the names the table keeps OUT on purpose resolve to nothing, and the names
 * of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every Tcl program there is. Each is pinned here with the file
 * count that decided it - in the 125 benign / 0 malware files the table was measured on (the measurement and its limits are in
 * the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_TCL

int main(void)
{
	static const struct nn_is is[] = {
		{ "binary.decode", KGENOME_NUCLEO_DECODE },
		{ "zlib.inflate", KGENOME_NUCLEO_DECODE },
		{ "zlib.decompress", KGENOME_NUCLEO_DECODE },
		{ "zlib.gunzip", KGENOME_NUCLEO_DECODE },
		{ "base64.decode", KGENOME_NUCLEO_DECODE },
		{ "uuencode.decode", KGENOME_NUCLEO_DECODE },
		{ "uplevel", KGENOME_NUCLEO_EVAL },
		{ "interp.eval", KGENOME_NUCLEO_EVAL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "interp.invokehidden", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "load", KGENOME_NUCLEO_LIB_OPEN },
		{ "ncgi.value", KGENOME_NUCLEO_REQUEST },
		{ "ncgi.input", KGENOME_NUCLEO_REQUEST },
		{ "ncgi.nvlist", KGENOME_NUCLEO_REQUEST },
		{ "cgi_import", KGENOME_NUCLEO_REQUEST },
		{ "env.QUERY_STRING", KGENOME_NUCLEO_REQUEST },
		{ "exec", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "file.delete", KGENOME_NUCLEO_FILE_DELETE },
		{ "file.rename", KGENOME_NUCLEO_FILE_RENAME },
		{ "file.copy", KGENOME_NUCLEO_WRITE },
		{ "file.attributes", KGENOME_NUCLEO_PERM_SET },
		{ "socket", KGENOME_NUCLEO_NET_CONNECT },
		{ "http.geturl", KGENOME_NUCLEO_HTTP_FETCH },
	};
	/* kept out on purpose; files of 125 benign / 0 malware that call it */
	static const struct nn_out out[] = {
		{ "eval", "78 / 0" },
		{ "proc", "68 / 0" },
		{ "source", "9 / 0" },
		{ "catch", "3 / 0" },
		{ "info", "5 / 0" },
		{ "pwd", "4 / 0" },
		{ "open", "0 / 0" },
		{ "puts", "1 / 0" },
		{ "after", "0 / 0" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"os.system",
		"system",
		"fork",
		"shell_exec",
		"base64_decode",
		"VirtualAlloc",
		"socket.tcp",
		"CreateProcessA",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"ncgi.value",
		"http.geturl",
		"uplevel",
		"interp.eval",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 6u },
		{ KGENOME_NUCLEO_EVAL, 2u },
		{ KGENOME_NUCLEO_DYNCALL, 2u },
		{ KGENOME_NUCLEO_DYNLOAD, 1u },
		{ KGENOME_NUCLEO_LIB_OPEN, 1u },
		{ KGENOME_NUCLEO_REQUEST, 5u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 1u },
		{ KGENOME_NUCLEO_FILE_DELETE, 1u },
		{ KGENOME_NUCLEO_FILE_RENAME, 1u },
		{ KGENOME_NUCLEO_WRITE, 1u },
		{ KGENOME_NUCLEO_PERM_SET, 1u },
		{ KGENOME_NUCLEO_NET_CONNECT, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 1u },
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
	NN_CK(rows == 24u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 0, "file.delete");
	nn_check_stable(TARGET, "file.delete");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "file.delete") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_tcl_names: the rows of the Tcl table, in the case it keeps, and the names it keeps out");
}
