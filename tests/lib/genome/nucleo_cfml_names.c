/*
 * nucleo_cfml_names - the rows of the ColdFusion table (tags and functions), and the names it keeps out
 * (libgenome/celllysis/nucleo_names_cfml.c): every row resolves to its capability and gives its own name back through its id,
 * the capability of every row is counted (a row moved to another word, added or dropped changes a count), the names the table
 * keeps OUT on purpose resolve to nothing, and the names of another platform or language are not in it.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does
 * not make", and a row added for one of them would put a node in every ColdFusion program there is. Each is pinned here with
 * the file count that decided it - in the 0 benign / 7 malware files the table was measured on (the measurement and its limits
 * are in the table's own comments) - so that a row that is added later has to answer for it.
 */

#include "nucleo_names_check.h"

#define TARGET KGENOME_NUCLEO_T_CFML

int main(void)
{
	static const struct nn_is is[] = {
		{ "ToBinary", KGENOME_NUCLEO_DECODE },
		{ "BinaryDecode", KGENOME_NUCLEO_DECODE },
		{ "URLDecode", KGENOME_NUCLEO_DECODE },
		{ "Decrypt", KGENOME_NUCLEO_CRYPTO },
		{ "Encrypt", KGENOME_NUCLEO_CRYPTO },
		{ "DecryptBinary", KGENOME_NUCLEO_CRYPTO },
		{ "EncryptBinary", KGENOME_NUCLEO_CRYPTO },
		{ "Evaluate", KGENOME_NUCLEO_EVAL },
		{ "Invoke", KGENOME_NUCLEO_DYNCALL },
		{ KGENOME_NUCLEO_DYNAMIC_NAME, KGENOME_NUCLEO_DYNCALL },
		{ "cfobject", KGENOME_NUCLEO_DYNLOAD },
		{ KGENOME_NUCLEO_DYNLOAD_NAME, KGENOME_NUCLEO_DYNLOAD },
		{ "cfinclude", KGENOME_NUCLEO_LIB_OPEN },
		{ "cfmodule", KGENOME_NUCLEO_LIB_OPEN },
		{ "form", KGENOME_NUCLEO_REQUEST },
		{ "url", KGENOME_NUCLEO_REQUEST },
		{ "cookie", KGENOME_NUCLEO_REQUEST },
		{ "GetHttpRequestData", KGENOME_NUCLEO_REQUEST },
		{ "cfexecute", KGENOME_NUCLEO_EXEC_IMAGE },
		{ "cffile", KGENOME_NUCLEO_FILE_OPEN },
		{ "FileRead", KGENOME_NUCLEO_FILE_OPEN },
		{ "FileOpen", KGENOME_NUCLEO_FILE_OPEN },
		{ "FileWrite", KGENOME_NUCLEO_WRITE },
		{ "FileCopy", KGENOME_NUCLEO_WRITE },
		{ "FileUpload", KGENOME_NUCLEO_WRITE },
		{ "FileDelete", KGENOME_NUCLEO_FILE_DELETE },
		{ "FileMove", KGENOME_NUCLEO_FILE_RENAME },
		{ "FileSetAccessMode", KGENOME_NUCLEO_PERM_SET },
		{ "FileSetLastModified", KGENOME_NUCLEO_TIMESTOMP },
		{ "cfhttp", KGENOME_NUCLEO_HTTP_FETCH },
		{ "cfftp", KGENOME_NUCLEO_NET_CONNECT },
		{ "cfregistry", KGENOME_NUCLEO_REG_SET },
	};
	/* kept out on purpose; files of 0 benign / 7 malware that call it */
	static const struct nn_out out[] = {
		{ "cfset", "0 / 3" },
		{ "cfif", "0 / 6" },
		{ "cfoutput", "0 / 6" },
		{ "cfloop", "0 / 1" },
		{ "cfquery", "0 / 1" },
		{ "cfmail", "0 / 0" },
		{ "cfdirectory", "0 / 0" },
		{ "cfschedule", "0 / 0" },
		{ "IsDefined", "0 / 6" },
		{ "StructKeyExists", "0 / 2" },
		{ "cgi", "0 / 2" },
	};
	/* names of another platform or language: not in this table */
	static const char *const absent[] = {
		"system",
		"fork",
		"chmod",
		"unlink",
		"popen",
		"base64_decode",
		"CreateProcessA",
		"VirtualAlloc",
		"shell_exec",
		"eval",
		"Invoke-Expression",
	};
	/* names that are this language's alone: in no other target's table */
	static const char *const only[] = {
		"cfexecute",
		"cfhttp",
		"GetHttpRequestData",
		"Evaluate",
	};
	/* how many rows each capability has: the capability of every row, without writing the table a second time */
	static const struct nn_cen cen[] = {
		{ KGENOME_NUCLEO_DECODE, 3u },
		{ KGENOME_NUCLEO_CRYPTO, 4u },
		{ KGENOME_NUCLEO_EVAL, 1u },
		{ KGENOME_NUCLEO_DYNCALL, 2u },
		{ KGENOME_NUCLEO_DYNLOAD, 2u },
		{ KGENOME_NUCLEO_LIB_OPEN, 2u },
		{ KGENOME_NUCLEO_REQUEST, 4u },
		{ KGENOME_NUCLEO_EXEC_IMAGE, 1u },
		{ KGENOME_NUCLEO_FILE_OPEN, 3u },
		{ KGENOME_NUCLEO_WRITE, 3u },
		{ KGENOME_NUCLEO_FILE_DELETE, 1u },
		{ KGENOME_NUCLEO_FILE_RENAME, 1u },
		{ KGENOME_NUCLEO_PERM_SET, 1u },
		{ KGENOME_NUCLEO_TIMESTOMP, 1u },
		{ KGENOME_NUCLEO_HTTP_FETCH, 1u },
		{ KGENOME_NUCLEO_NET_CONNECT, 1u },
		{ KGENOME_NUCLEO_REG_SET, 1u },
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
	NN_CK(rows == 32u && rows == sizeof is / sizeof is[0]);
	nn_check_fold(TARGET, 1, "cfexecute");
	nn_check_stable(TARGET, "cfexecute");
	/* a call of a value and a class named by a value are the rows no language writes: the same two names in every table */
	NN_CK(kgenome_nucleo_cap_of_name(TARGET, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_DYNCALL);
	NN_CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE &&
	      kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, KGENOME_NUCLEO_DYNAMIC_NAME) == KGENOME_NUCLEO_NONE);
	NN_CK(kgenome_nucleo_cap_of_name(99u, "cfexecute") == KGENOME_NUCLEO_NONE);   /* a target nobody has */
	NN_DONE("nucleo_cfml_names: the rows of the ColdFusion table, in the case it keeps, and the names it keeps out");
}
