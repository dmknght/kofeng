/*
 * diag_str.c - the names read at call sites: the table that holds them and its lookups.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

/*
 * FNV-1a over the name, with the capability AND THE NODE mixed into the seed
 * so the same word handed to two different calls - or read at two different
 * places - is two different keys. 32 bits is enough
 * because every probe that matches on it then compares the bytes: a collision
 * costs one strcmp and cannot make a name appear.
 */
/* KNOWN DEFECT REV-D7c (2026-10-24, Inference) [sev L]: str_hash (the string table) is a hand-rolled open-addressing table with an unseeded multiplicative
 * hash, not the shared helper (diag_oatab.h / kof_hash64_slot): CLAUDE.md rule 2. Trigger: keys chosen by the file that
 * collide in the top bits. Effect: probe chains grow (the G1 flood in the script tables took 20.4 s for 65536 names).
 * Reproducer: none (review_arch D7, read). Fix: build it on kgenome_oatab (seeded, one probe step) like diag_text_sum. */
static uint32_t str_hash(uint16_t cap, uint16_t node, const char *s)
{
	uint32_t h = KOF_HASH_INIT ^ ((uint32_t)cap * 0x9e3779b1u) ^
		     ((uint32_t)node * 0x85ebca6bu);

	while (*s)
		h = kof_hash_step(h, (uint8_t)*s++);
	return h;
}

/* (Re)build the table for the current entry capacity. Failure leaves the old
 * one in place and the caller notes the status. The table is charged to the
 * ledger: the new one is charged before the old one is given back. */
static int str_table_build(struct kgenome_diag_scan *s)
{
	uint32_t sz = 2u * s->cap_str, i;
	uint16_t *t;
	uint64_t old_bytes = s->str_tab ? ((uint64_t)s->str_tmask + 1u) * sizeof *t : 0;

	if (!kgenome_ledger_charge(&s->led, (uint64_t)sz * sizeof *t))
		return 0;
	t = calloc(sz, sizeof *t);
	if (!t) {
		kgenome_ledger_release(&s->led, (uint64_t)sz * sizeof *t);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	kgenome_ledger_release(&s->led, old_bytes);
	for (i = 0; i < s->n_str; i++) {
		uint32_t p = s->str[i].hash & (sz - 1u);

		while (t[p])
			p = (p + 1u) & (sz - 1u);
		t[p] = (uint16_t)(i + 1u);
	}
	free(s->str_tab);
	s->str_tab = t;
	s->str_tmask = sz - 1u;
	return 1;
}

int kgenome_diag_str_add(struct kgenome_diag_scan *s, uint16_t cap, uint16_t node,
		     const char *name)
{
	uint32_t h, p;
	size_t n;

	if (!s || !name || !*name)
		return 0;
	n = strlen(name);
	if (n > KGENOME_DIAG_STR_MAX) {
		/* Refused, COUNTED, and said: a diagnose reading this name cannot
		 * match it, which is "cannot say" and not "absent". */
		s->n_str_refused++;
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return 0;
	}
	h = str_hash(cap, node, name);
	/* ALREADY HERE? One probe, where this was a strcmp against every entry. */
	if (s->str_tab)
		for (p = h & s->str_tmask; s->str_tab[p];
		     p = (p + 1u) & s->str_tmask) {
			const struct kgenome_diag_str *e =
				&s->str[s->str_tab[p] - 1u];

			if (e->hash == h && e->cap == cap && e->node == node &&
			    !strcmp(e->s, name))
				return 0;
		}
	if (s->n_str >= kgenome_diag_name_limit(s)) {
		s->n_str_refused++;
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return 0;
	}
	if (s->n_str == s->cap_str) {
		uint32_t nc = s->cap_str ? s->cap_str * 2u : 16u;
		struct kgenome_diag_str *nv;
		uint32_t old = s->cap_str;
		uint64_t grow = (uint64_t)(nc - old) * sizeof *nv;

		if (!kgenome_ledger_charge(&s->led, grow)) {
			s->n_str_refused++;
			return 0;
		}
		nv = realloc(s->str, nc * sizeof *nv);
		if (!nv) {
			kgenome_ledger_release(&s->led, grow);
			kgenome_diag_note(s, KGENOME_NOMEM);
			s->n_str_refused++;
			return 0;
		}
		s->str = nv;
		s->cap_str = nc;
		if (!str_table_build(s)) {
			/* The entries are fine; the new slots are not offered, and
			 * the array goes back to what the ledger still charges. */
			s->cap_str = old;
			if (old) {
				void *back = realloc(s->str, old * sizeof *nv);

				if (back)
					s->str = back;
			} else {
				free(s->str);
				s->str = NULL;
			}
			kgenome_ledger_release(&s->led, grow);
			s->n_str_refused++;
			return 0;
		}
	}
	s->str[s->n_str].cap = cap;
	s->str[s->n_str].node = node;
	s->str[s->n_str].hash = h;
	memcpy(s->str[s->n_str].s, name, n + 1u);
	s->n_str++;
	for (p = h & s->str_tmask; s->str_tab[p]; p = (p + 1u) & s->str_tmask)
		;
	s->str_tab[p] = (uint16_t)s->n_str;
	return 1;
}

/* Was `name` read at THIS node, by a call of THIS capability. One probe. */
int kgenome_diag_str_at_node(const struct kgenome_diag_scan *s, uint16_t cap,
		       uint16_t node, const char *name)
{
	uint32_t h, p;

	if (!s || !name || !s->str_tab)
		return 0;
	h = str_hash(cap, node, name);
	for (p = h & s->str_tmask; s->str_tab[p]; p = (p + 1u) & s->str_tmask) {
		const struct kgenome_diag_str *e = &s->str[s->str_tab[p] - 1u];

		if (e->hash == h && e->cap == cap && e->node == node &&
		    !strcmp(e->s, name))
			return 1;
	}
	return 0;
}

const char *kgenome_diag_str_at(const struct kgenome_diag_scan *s, uint16_t cap,
			    uint32_t i)
{
	uint32_t k;

	if (!s)
		return NULL;
	for (k = 0; k < s->n_str; k++)
		if (s->str[k].cap == cap && i-- == 0u)
			return s->str[k].s;
	return NULL;
}

uint32_t kgenome_diag_str_count(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t k, n = 0;

	if (!s)
		return 0;
	for (k = 0; k < s->n_str; k++)
		if (s->str[k].cap == cap)
			n++;
	return n;
}
