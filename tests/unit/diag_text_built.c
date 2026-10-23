/*
 * diag_text_built - a function name a script builds with a function call, found through the engine's hook.
 *
 * `str_replace('k', '', 'ckrekatek_fuknkkction')` is the classic way to hide a name, and what str_replace does is not the
 * route's: the engine hands it kof_script_apply (kuncoat's algorithms), the same hook the form and the gate use. What is
 * pinned is the node the call makes, that its name was MADE, and the links its arguments get - for each function of the
 * language's table, and for the calls the table has no place for, which are not followed.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

#include "../../libkofeng/analyzers/parsers/scripts/script_apply.h"
#include "../lib/genome/diag_text_graph.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static struct kgenome_diag_scan *scan(const char *src)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = KGENOME_TEXTUAL_LANG_PHP,
					    .apply = kof_script_apply };

	return kgenome_diag_scan_text(&rq);
}

int main(void)
{
	/* the name is MADE and the call is exec (or eval) with the request reaching it */
	static const struct { const char *src; uint16_t cap; int nodes; int req_to; } yes[] = {
		/* hoho.php's own: create_function through str_replace */
		{ "<?php $l = str_replace('k', '', 'ckrekatek_fuknkkction'); $l('', $c);", KGENOME_NUCLEO_CREATE, 1, 0 },
		{ "<?php $n = str_replace('XY', '', 'sXYysXYtem'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = str_replace('s', 'sys', 's'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 0, 0 },     /* s -> sys: "sys" is no table name */
		{ "<?php $n = strrev('metsys'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = str_rot13('flfgrz'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = strtoupper('sYsTeM'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = strtolower('SYSTEM'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = ucfirst('system'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },              /* "System" is the function too: php names are not case sensitive */
		{ "<?php $n = substr('xxsystemxx', 2, 6); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = substr('xxsystem', 2); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = substr('systemxx', 0, -2); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = substr('xxsystem', -6); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = hex2bin('73797374656d'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = base64_decode('c3lzdGVt'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = strtr('zyztem', 'z', 's'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = trim('  system  '); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = ltrim('  system'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = rtrim('system  '); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = urldecode('sys%74em'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = rawurldecode('sys%74em'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* functions nested, and the name inside brackets */
		{ "<?php $n = (str_replace('X', '', 'sXyXs') . strrev('met')); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		{ "<?php $n = strrev(str_rot13('zrgflf')); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* in an array read by an index */
		{ "<?php $fc = ['md5', str_rot13('flfgrz')]; $fc[1]($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
		/* the function's own spelling is any case in php */
		{ "<?php $n = STR_ReplacE('k', '', 'sykstkem'); $n($_GET['c']);", KGENOME_NUCLEO_EXEC_IMAGE, 1, 1 },
	};
	/* NOT a name: a call the table has no place for in its signature, and bytes the function does not read */
	static const char *const no[] = {
		"<?php $n = str_replace(array('k'), '', 'sykstkem'); $n($_GET['c']);",         /* the array form */
		"<?php $n = str_replace('k', '', 'sykstkem', $c); $n($_GET['c']);",            /* the fourth argument */
		"<?php $n = trim('xsystemx', 'x'); $n($_GET['c']);",                           /* a character list */
		"<?php $n = base64_decode('c3lzdGVt', true); $n($_GET['c']);",                 /* the strict flag */
		"<?php $n = strtr('zyztem', 'zy', 's'); $n($_GET['c']);",                      /* lists of unequal length */
		"<?php $n = substr('xxsystem', 'a'); $n($_GET['c']);",                         /* a start that is no number */
		"<?php $n = hex2bin('7'); $n($_GET['c']);",                                    /* an odd digit */
		"<?php $n = rawurldecode('sys+tem'); $n($_GET['c']);",                         /* "+" stays: this is no function name */
	};
	uint32_t i;

	for (i = 0; i < sizeof yes / sizeof yes[0]; i++) {
		struct kgenome_diag_scan *s = scan(yes[i].src);

		CK(s != NULL, "scan of %s", yes[i].src);
		if (!s)
			continue;
		CK(count(s, yes[i].cap) == yes[i].nodes, "nodes %d, wanted %d of %u in: %s", count(s, yes[i].cap), yes[i].nodes, yes[i].cap, yes[i].src);
		CK(built_node(s, yes[i].cap) == yes[i].nodes, "the name was made: %d in: %s", yes[i].nodes, yes[i].src);
		CK(linked(s, KGENOME_NUCLEO_REQUEST, yes[i].cap, 0xff) == yes[i].req_to, "request link %d in: %s", yes[i].req_to, yes[i].src);
		kgenome_diag_scan_free(s);
	}
	for (i = 0; i < sizeof no / sizeof no[0]; i++) {
		struct kgenome_diag_scan *s = scan(no[i]);

		CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "no exec node in: %s", no[i]);
		kgenome_diag_scan_free(s);
	}
	printf("diag text built: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
