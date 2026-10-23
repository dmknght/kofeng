/*
 * genome / diag_text_callsem - a call is matched to its row of the language's call semantics (callsem_named in diag_text.c) by its name exactly: the whole name, in the case the
 * language folds to.
 *
 * php's `intval` is a CLEAN call: what it is given does not reach the sink, so `system(intval($_GET['c']))` has no link from the request to system where `system(intvx($_GET['c']))`
 * (a name no row has) does. Read through that difference:
 *   the row is found                  intval cuts the link (fewer links than intvx);
 *   the case folds                    INTVAL and IntVal are the row too (php function names are not case sensitive);
 *   a PREFIX of a row is not the row  `intva(` is an unknown call, as `intvx(` is;
 *   a name that holds a row is not it `intvalx(` likewise.
 *
 * usage: diag_text_callsem
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <textual/textual.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint32_t links(const char *call)
{
	char t[256];
	struct kgenome_diag_text_req rq = { .lang = KGENOME_TEXTUAL_LANG_PHP };
	struct kgenome_diag_scan *s;
	uint32_t i, n = 0;

	snprintf(t, sizeof t, "<?php system(%s($_GET['c'])); ?>", call);
	rq.base = (const uint8_t *)t;
	rq.size = strlen(t);
	s = kgenome_diag_scan_text(&rq);
	for (i = 0; s && i < kgenome_diag_scan_count(s); i++)
		n += kgenome_diag_scan_at(s, i)->n_in;
	kgenome_diag_scan_free(s);
	return n;
}

int main(void)
{
	uint32_t unknown = links("intvx"), clean = links("intval");

	CK(unknown > clean, "the row cuts the link: intval %u links, a name no row has %u", clean, unknown);
	CK(links("INTVAL") == clean, "the case folds: INTVAL %u, intval %u", links("INTVAL"), clean);
	CK(links("IntVal") == clean, "mixed case folds");
	CK(links("intva") == unknown, "a prefix of a row is not the row: intva %u, unknown %u", links("intva"), unknown);
	CK(links("i") == unknown && links("int") == unknown, "shorter prefixes are not rows");
	CK(links("intvalx") == unknown, "a name holding a row is not the row: %u", links("intvalx"));
	CK(links("xintval") == unknown, "nor one that ends in it: %u", links("xintval"));
	printf("genome diag_text_callsem: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
