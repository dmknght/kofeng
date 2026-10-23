/*
 * genome / nucleo_index - the lookup of a name in the vocabulary's tables (celllysis/nucleo.c) against the scan it replaced.
 *
 * The lookup is a hash index over the rows, built on first use. What it must keep is the scan's answer: the FIRST row whose name is the asked one, where a `fold` table
 * ignores ASCII case and an "@" in the asked name ends it (a version suffix: "open64@@GLIBC_2.2.5" is "open64"). The reference below is the scan, written here from
 * those two sentences, over the tables' own rows (nucleo_private.h). It is asked, for every table and every row:
 *   the row's own name, upper-cased and lower-cased, with a version suffix, with a byte added and with one cut off (those are not rows, unless another row is that
 *   name), a name of the same hash class (the other rows' names with their first letter changed), and the empty and the lone "@" - and the same questions of random
 *   names. The answer of kgenome_nucleo_name_lookup (capability and id), cap_of_name and name_id must be the reference's, and name_of(id) the row's name.
 *   A duplicate name in a table (there is none today: the test says so and would say if one came) must resolve to the first.
 *
 * usage: nucleo_index
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <celllysis/nucleo.h>
#include <celllysis/nucleo_private.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static const struct kgenome_nucleo_names *const all[] = {
	&kgenome_nucleo_names_elf, &kgenome_nucleo_names_pe, &kgenome_nucleo_names_php, &kgenome_nucleo_names_js, &kgenome_nucleo_names_py,
	&kgenome_nucleo_names_perl, &kgenome_nucleo_names_ruby, &kgenome_nucleo_names_lua, &kgenome_nucleo_names_tcl, &kgenome_nucleo_names_sh,
	&kgenome_nucleo_names_bat, &kgenome_nucleo_names_psh, &kgenome_nucleo_names_vbs, &kgenome_nucleo_names_dotnet, &kgenome_nucleo_names_java,
	&kgenome_nucleo_names_cfml
};
#define NT (sizeof all / sizeof all[0])

static int ref_same(const char *a, const char *b, int fold)
{
	for (;;) {
		unsigned char x = (unsigned char)*a, y = (unsigned char)*b;

		if (fold) {
			if (x >= 'A' && x <= 'Z')
				x = (unsigned char)(x + 32);
			if (y >= 'A' && y <= 'Z')
				y = (unsigned char)(y + 32);
		}
		if (!x)
			return !y || y == '@';
		if (x != y)
			return 0;
		a++;
		b++;
	}
}

/* the scan: the first row of table `t` that is `sym`; its id (position over all the tables, 1-based) and capability */
static int ref_find(size_t t, const char *sym, uint16_t *cap, uint16_t *id)
{
	uint32_t base = 0, i;
	size_t k;

	for (k = 0; k < t; k++)
		base += all[k]->n;
	*cap = KGENOME_NUCLEO_NONE;
	*id = 0;
	if (!*sym)
		return 0;
	for (i = 0; i < all[t]->n; i++)
		if (ref_same(all[t]->row[i].name, sym, all[t]->fold)) {
			*cap = all[t]->row[i].cap;
			*id = (uint16_t)(base + i + 1u);
			return 1;
		}
	return 0;
}

static void ask(size_t t, const char *sym)
{
	uint16_t rc, rid, c, id = 0xffffu;

	(void)ref_find(t, sym, &rc, &rid);
	c = kgenome_nucleo_name_lookup(all[t]->target, sym, &id);
	CK(c == rc);
	CK(id == rid);
	CK(kgenome_nucleo_name_lookup(all[t]->target, sym, NULL) == rc);
	CK(kgenome_nucleo_cap_of_name(all[t]->target, sym) == rc);
	CK(kgenome_nucleo_name_id(all[t]->target, sym) == rid);
	if (rid)
		CK(kgenome_nucleo_name_of(rid) != NULL && ref_same(kgenome_nucleo_name_of(rid), sym, all[t]->fold));
}

static uint32_t rs = 99u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 8;
}

int main(void)
{
	size_t t;
	uint32_t i, n = 0, dup = 0, r;
	char b[256];

	for (t = 0; t < NT; t++) {
		/* the tables the index can hold: no empty name, no "@" in a name - the build gives the scan up otherwise, and the test checks the same either way */
		for (i = 0; i < all[t]->n; i++) {
			const char *nm = all[t]->row[i].name;
			size_t len = strlen(nm), k;
			uint32_t j;

			CK(len > 0 && len < 100 && !strchr(nm, '@'));
			for (j = 0; j < i; j++)
				if (ref_same(all[t]->row[j].name, nm, all[t]->fold) && ref_same(nm, all[t]->row[j].name, all[t]->fold))
					dup++;
			ask(t, nm);
			for (k = 0; k <= len; k++)
				b[k] = (char)(all[t]->fold && nm[k] >= 'a' && nm[k] <= 'z' ? nm[k] - 32 : nm[k]);
			ask(t, b);
			for (k = 0; k <= len; k++)
				b[k] = (char)(nm[k] >= 'A' && nm[k] <= 'Z' ? nm[k] + 32 : nm[k]);
			ask(t, b);
			snprintf(b, sizeof b, "%s@@GLIBC_2.2.5", nm);
			ask(t, b);
			snprintf(b, sizeof b, "%s@", nm);
			ask(t, b);
			snprintf(b, sizeof b, "%sx", nm);
			ask(t, b);
			snprintf(b, sizeof b, "_%s", nm);
			ask(t, b);
			if (len > 1) {
				memcpy(b, nm, len - 1u);
				b[len - 1u] = 0;
				ask(t, b);
			}
			snprintf(b, sizeof b, "%s", nm);
			b[0] = (char)(b[0] ^ 1);
			ask(t, b);
			snprintf(b, sizeof b, "@%s", nm);
			ask(t, b);
			n++;
		}
		ask(t, "");
		ask(t, "@");
		ask(t, "@@x");
		for (r = 0; r < 4000; r++) {
			uint32_t len = 1u + rnd() % 14u, k;

			for (k = 0; k < len; k++)
				b[k] = (char)("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789.@"[rnd() % 66u]);
			b[len] = 0;
			ask(t, b);
		}
	}
	/* the generated index: one entry per table in the order of the tables, its row count the table's, a power-of-two capacity at or over twice the rows, and every row
	 * once among the slots (a stale file or a hand edit fails here before it fails a lookup) */
	for (t = 0; t < NT; t++) {
		const struct kgenome_nucleo_index *ix = &kgenome_nucleo_index[t];
		uint32_t seen = 0, c;
		uint8_t *hit = calloc(all[t]->n + 1u, 1u);

		CK(ix->n == all[t]->n);
		CK(ix->cap >= 4u && (ix->cap & (ix->cap - 1u)) == 0u && ix->cap >= 2u * all[t]->n && ix->cap / 2u < 2u * all[t]->n + 4u);
		for (c = 0; c < ix->cap; c++) {
			if (!ix->slot[c])
				continue;
			CK(ix->slot[c] <= all[t]->n);
			if (ix->slot[c] <= all[t]->n) {
				CK(!hit[ix->slot[c]]);
				hit[ix->slot[c]] = 1;
				seen++;
			}
		}
		CK(seen == all[t]->n);
		free(hit);
	}
	CK(n > 1000u);
	CK(dup == 0u);
	/* an id is a position over the tables laid end to end, and name_of turns it back: the first and the last row of every table */
	for (t = 0; t < NT; t++) {
		uint16_t c, id;

		(void)kgenome_nucleo_name_lookup(all[t]->target, all[t]->row[0].name, &id);
		CK(id != 0 && strcmp(kgenome_nucleo_name_of(id), all[t]->row[0].name) == 0);
		(void)kgenome_nucleo_name_lookup(all[t]->target, all[t]->row[all[t]->n - 1u].name, &id);
		CK(id != 0 && strcmp(kgenome_nucleo_name_of(id), all[t]->row[all[t]->n - 1u].name) == 0);
		c = kgenome_nucleo_name_lookup(0xfeu, "x", &id);        /* a target that is none */
		CK(c == KGENOME_NUCLEO_NONE && id == 0);
	}
	printf("genome nucleo_index: %u names, %s\n", n, fails ? "FAILED" : "ok");
	return fails != 0;
}
