/*
 * nucleo_names_cfml.c - what a ColdFusion (CFML) name means: the tags and the functions, in the vocabulary a native
 * program's imports are read in.
 *
 * CFML has two syntaxes for one runtime, and a row is whichever the page writes: a TAG is its name with the angle brackets
 * off and the "cf" kept ("cfexecute" is `<cfexecute ...>` and `cfexecute(...)` in script), a FUNCTION is its name
 * ("Evaluate"). CFML does not care about case (`fold`). The attributes of a tag - the `action` of cffile, the `type` of
 * cfobject - are the matcher's: where one tag is several capabilities by an attribute (cffile reads, writes, copies and
 * deletes) the row is the one the vocabulary calls the weaker, as for PHP's fopen. A scope of request data is spelled as the
 * scope ("form", "url", "cookie"): the key after it (`form.cmd`) is the matcher's, as PHP's `_GET`. A Java object made by
 * `createObject("java", "java.lang.Runtime")` has the Java table's names, looked up with the class the string names.
 *
 * The evidence is 7 CFML files: the cfexec shells of the corpus (the Laudanum and Webshell-Collection cmd shells, a SQL
 * shell and a CF-administrator one). There is NO benign CFML on this machine, so no row has a benign count; the rows are the
 * tags and functions that run, read, write and request and are documented as such. Every row is [Unverified] against benign
 * code.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: ToBinary and BinaryDecode make bytes out of base64 or hex text, URLDecode decodes the percent form; with a key:
	 * Decrypt and Encrypt. [Unverified: no occurrence.]
	 */
	{ .name = "ToBinary", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "BinaryDecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "URLDecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "Decrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "Encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "DecryptBinary", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "EncryptBinary", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * EVAL: Evaluate runs a string as an expression, now. DYNCALL: Invoke calls the method whose name it is given (cfinvoke with
	 * a method attribute that is a value is the tag form: not a row, because the attribute is how every component is called);
	 * the row "(dynamic)" is a call of a value. DYNLOAD: the row "(load)" is `createObject(type, name)` and `<cfobject
	 * type="..." name=...>` with a name that is a value; cfobject and cfimport instantiate a class or a tag library by its name,
	 * which is the act. [Unverified: no occurrence.]
	 */
	{ .name = "Evaluate", .cap = KGENOME_NUCLEO_EVAL },
	{ .name = "Invoke", .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	{ .name = "cfobject", .cap = KGENOME_NUCLEO_DYNLOAD },
	{ .name = KGENOME_NUCLEO_DYNLOAD_NAME, .cap = KGENOME_NUCLEO_DYNLOAD },
	/*
	 * LIB_OPEN: cfinclude runs another template in this one (no benign set, 1/7 malware) and cfmodule runs a custom tag: the
	 * same act as a library load, and the operand is what makes it a shell.
	 */
	{ .name = "cfinclude", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "cfmodule", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * REQUEST: what the sender chose: the form and url scopes (no benign set, 6/7 malware is the first line of the cfexec
	 * shells: `form.cmd`), the cookie scope, and GetHttpRequestData, which hands back the whole request (no benign set, 2/7
	 * malware).
	 */
	{ .name = "form", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "url", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "cookie", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "GetHttpRequestData", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * PROCESS: cfexecute is the tag the cmd shells are made of (no benign set, 5/7 malware: the whole of what they do); it is
	 * the first thing an administrator disables, and the shells say so. FILE: cffile reads, writes, appends, copies, moves,
	 * renames, deletes and receives an upload by its `action` (no benign set, 0/7 malware); the functions are the same acts one
	 * by one. NETWORK: cfhttp fetches a URL in one call and cfftp connects. REGISTRY: cfregistry reads and writes by its action;
	 * the weaker word is the write, as the native table keeps only writes.
	 */
	{ .name = "cfexecute", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "cffile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "FileRead", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "FileOpen", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "FileWrite", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "FileCopy", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "FileUpload", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "FileDelete", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "FileMove", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "FileSetAccessMode", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "FileSetLastModified", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "cfhttp", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "cfftp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "cfregistry", .cap = KGENOME_NUCLEO_REG_SET },
	/*
	 * LEFT OUT, because the name is not the evidence (and there is no benign CFML here to count it in, so this is the rule
	 * applied from the language): cfset, cfif, cfelse, cfelseif, cfoutput, cfloop, cfparam, cfscript, cfsavecontent, cfsetting,
	 * cfapplication, cfcomponent, cffunction, cfargument, cfreturn, cfdump, cfabort, cfheader, cflocation, cflog, cfcontent (the
	 * language and the page); cfquery and cfstoredproc (a database is not in the vocabulary), cfmail, cfldap, cfpop, cfdirectory
	 * (a listing, and by its action a delete: left to a later pass for lack of an occurrence), cfzip, cfschedule (persistence:
	 * no word), cfthread; IsDefined, StructKeyExists, Replace, ListToArray, HTMLEditFormat, CreateTimeSpan, GetDataSourceService
	 * and GetDataSources (the CF-administrator shell's own calls: a datasource is a database); the scope cgi (cgi.script_name is
	 * the page's own name, as PHP's $_SERVER). NOT NAMED because the vocabulary has no word: a database, and the scheduled task.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_cfml = {
	.target = KGENOME_NUCLEO_T_CFML, .fold = 1, .row = rows, .n = sizeof rows / sizeof rows[0]
};
