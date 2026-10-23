/*
 * nucleo_php_names - what a PHP function name means in the vocabulary (libgenome/celllysis/nucleo_names_php.c): the rows that are there
 * for the shells of the corpus, the rows that complete a pair, and the names the table keeps OUT on purpose.
 *
 * The third group is as much the table as the first: "a name is a row only when it carries a claim the ordinary program does not make", and
 * a row added for `fread` or `mkdir` would put a node in every php file there is. They are pinned here with the count of the 76 shells of the
 * corpus that call them and of the 1,073 files of WordPress, so that a row that is added later has to answer for that.
 */

#include <kgenome.h>
#include <celllysis/nucleo.h>
#include <celllysis/capability_ids.h>

#include <stdio.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static uint16_t php(const char *name)
{
	return kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PHP, name);
}

int main(void)
{
	static const struct { const char *name; uint16_t cap; } is[] = {
		/* lookups: gethostbyname was the only one; 4 shells call gethostbyaddr, 2 dns_get_record, a resolver tool offered through the web server */
		{ "gethostbyname", KGENOME_NUCLEO_DNS }, { "gethostbynamel", KGENOME_NUCLEO_DNS }, { "gethostbyaddr", KGENOME_NUCLEO_DNS },
		{ "dns_get_record", KGENOME_NUCLEO_DNS }, { "checkdnsrr", KGENOME_NUCLEO_DNS }, { "dns_check_record", KGENOME_NUCLEO_DNS },
		{ "getmxrr", KGENOME_NUCLEO_DNS }, { "dns_get_mx", KGENOME_NUCLEO_DNS },
		/* an ftp connection is a connection: 8 shells call ftp_connect */
		{ "ftp_connect", KGENOME_NUCLEO_NET_CONNECT }, { "ftp_ssl_connect", KGENOME_NUCLEO_NET_CONNECT },
		/* the stream API's accept and the other directions of its socket */
		{ "stream_socket_server", KGENOME_NUCLEO_NET_LISTEN }, { "stream_socket_accept", KGENOME_NUCLEO_NET_ACCEPT },
		{ "socket_create_listen", KGENOME_NUCLEO_NET_LISTEN }, { "stream_socket_recvfrom", KGENOME_NUCLEO_NET_READ },
		{ "stream_socket_sendto", KGENOME_NUCLEO_NET_WRITE }, { "socket_listen", KGENOME_NUCLEO_NET_LISTEN },
		{ "socket_accept", KGENOME_NUCLEO_NET_ACCEPT },
		/* some that were there, so that a row moved by mistake is seen */
		{ "system", KGENOME_NUCLEO_EXEC_IMAGE }, { "base64_decode", KGENOME_NUCLEO_DECODE }, { "eval", KGENOME_NUCLEO_EVAL },
		{ "_GET", KGENOME_NUCLEO_REQUEST }, { "unlink", KGENOME_NUCLEO_FILE_DELETE }, { "curl_exec", KGENOME_NUCLEO_HTTP_FETCH },
	};
	/* kept out on purpose; shells of 76 / files of 1,073 of WordPress that call it */
	static const struct { const char *name; const char *why; } out[] = {
		{ "fread", "19 / 17: every file read" }, { "fgets", "16 / 7" }, { "mkdir", "16 / 9: no capability says 'create a directory'" },
		{ "chdir", "24 / 6" }, { "symlink", "7 / 2: no capability says 'link'" }, { "stream_set_blocking", "9 / 2" },
		{ "mysql_query", "12 / 0: a database is not in the vocabulary" }, { "proc_close", "10 / 0" }, { "fclose", "33 / 33" },
		{ "chr", "11 / 13: every program" }, { "ord", "15 / 12" }, { "mail", "13 / 3" }, { "header", "35 / 61" },
		{ "ini_set", "23 / 7" }, { "set_time_limit", "28 / 9" }, { "error_reporting", "38 / 12" }, { "scandir", "13 / 3" },
		{ "php_uname", "19 / 2" }, { "phpinfo", "14 / 1" }, { "getenv", "11 / 3" }, { "md5", "20 / 69" }, { "curl_setopt", "10 / 5" },
		{ "preg_replace", "16 / 132: eval only with /e, which an argument decides" }, { "array_map", "11 / 105" },
	};
	uint32_t i;

	for (i = 0; i < sizeof is / sizeof is[0]; i++) {
		if (php(is[i].name) != is[i].cap) {
			printf("  FAIL %s is %s, wanted %s\n", is[i].name, kgenome_nucleo_cap_name(php(is[i].name)), kgenome_nucleo_cap_name(is[i].cap));
			fails++;
		}
	}
	CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PHP, "") == KGENOME_NUCLEO_NONE);
	for (i = 0; i < sizeof out / sizeof out[0]; i++)
		if (php(out[i].name) != KGENOME_NUCLEO_NONE) {
			printf("  FAIL %s has a row (%s) and the table keeps it out: %s\n", out[i].name, kgenome_nucleo_cap_name(php(out[i].name)), out[i].why);
			fails++;
		}
	{
		char up[32];

		/* php does not care about the case of a function name */
		strcpy(up, "GetHostByAddr");
		CK(php(up) == KGENOME_NUCLEO_DNS);
		strcpy(up, "FTP_CONNECT");
		CK(php(up) == KGENOME_NUCLEO_NET_CONNECT);
		/* and the table is the PHP one: the same word in the ELF table is not a PHP function */
		CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, "ftp_connect") == KGENOME_NUCLEO_NONE);
	}
	if (fails) {
		printf("nucleo_php_names: %d failed\n", fails);
		return 1;
	}
	printf("nucleo_php_names: the rows of the PHP table, in both cases, and the names it keeps out - ok\n");
	return 0;
}
