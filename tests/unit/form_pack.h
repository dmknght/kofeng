/*
 * form_pack.h - what the memory tests of the diagnose forms share (mem_diag_forms, mem_oom_open): files, a block made of the bytes of a seed, and a
 * pack of diagnose records written in the .kdig layout, each a similarity form (blocks, one matcher a block, "any of them").
 *
 * Every byte of a block is above 0x7f: a printable run and a NUL make a STRING CLUSTER, which the scanner cuts out as a unit of its own
 * (kgenome_mutation_units), so a block hashed over the whole of such bytes is not the block the object feeds (1 in 2000 seeds).
 */

#ifndef KOFENG_TESTS_FORM_PACK_H
#define KOFENG_TESTS_FORM_PACK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/pack/diagform.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include <celllysis/mutation.h>
#include <kofmod/kofsig.h>

/* ---- files -------------------------------------------------------------------------- */

static __attribute__((unused)) int write_file(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n && fwrite(p, 1, n, f) != n) {
		fclose(f);
		return 0;
	}
	return fclose(f) == 0;
}

static __attribute__((unused)) uint8_t *read_file(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b;
	long L;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	L = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)L + 1u);
	if (b && fread(b, 1, (size_t)L, f) != (size_t)L) {
		free(b);
		b = NULL;
	}
	fclose(f);
	if (b)
		*n = (size_t)L;
	return b;
}

static __attribute__((unused)) int copy_pack(const char *from_dir, const char *leaf, const char *to_dir)
{
	char a[700], b[700];
	size_t n = 0;
	uint8_t *p;
	int r;

	snprintf(a, sizeof a, "%s/%s", from_dir, leaf);
	snprintf(b, sizeof b, "%s/%s", to_dir, leaf);
	p = read_file(a, &n);
	r = p && n && write_file(b, p, n);
	free(p);
	return r;
}

static __attribute__((unused)) void rm_all(const char *dir)
{
	char cmd[800];

	snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
	(void)system(cmd);
}

static __attribute__((unused)) void put16(uint8_t *b, unsigned at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1u] = (uint8_t)(v >> 8); }
static __attribute__((unused)) void put32(uint8_t *b, unsigned at, uint32_t v) { put16(b, at, (uint16_t)v); put16(b, at + 2u, (uint16_t)(v >> 16)); }

/* ---- bytes and the block they make --------------------------------------------------- */

#define BLK 2048u

static __attribute__((unused)) void make_bytes(uint8_t *b, uint32_t seed)
{
	uint32_t i;

	/* Every byte is above 0x7f: a printable run and a NUL make a STRING CLUSTER, which the scanner cuts out as a unit of its own
	 * (kgenome_mutation_units), so a block hashed over the whole of such bytes is not the block the object feeds (1 in 2000 here).
	 * A mixing function of (seed, i), not a generator walked from the seed: two seeds of a walked xorshift lie a few steps apart on
	 * one cycle often enough (12 pairs in 5000) that their blocks overlap and one scores in the other. */
	for (i = 0; i < BLK; i++) {
		uint64_t x = ((uint64_t)seed << 32 | i) + 0x9E3779B97F4A7C15ull;

		x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
		x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
		b[i] = (uint8_t)(0x80u | ((x ^ (x >> 31)) >> 8));
	}
}

/* The seed of block `j` of form `k`: never zero, distinct for every pair. */
static __attribute__((unused)) uint32_t seed_of(uint32_t k, uint32_t j)
{
	return 0x9E3779B1u * (k * 64u + j + 1u);
}

/* ---- a record of a diagnose that is a similarity form -------------------------------- */

/* One record: header, name, no node, then `sections` (already cut). */
static __attribute__((unused)) size_t record(uint8_t *out, const char *name, const uint8_t *sections, size_t sn)
{
	size_t at = 0, nl = strlen(name);

	out[at++] = 0;
	out[at++] = 0;
	out[at++] = 0;
	out[at++] = (uint8_t)nl;
	memcpy(out + at, name, nl);
	at += nl;
	out[at++] = 0;
	memcpy(out + at, sections, sn);
	return at + sn;
}

/*
 * A form of `nb` blocks, block j made of the bytes of seed_of(k, j), one matcher a block (every block at a hundred percent)
 * and the expression "any of them": a scan of the bytes of ONE of its blocks matches it and no other form.
 */
static __attribute__((unused)) size_t form_record_in(uint8_t *rec, const char *name, uint32_t k, uint32_t nb, uint32_t mask)
{
	struct kof_form *f = kof_form_new();
	uint8_t blk[BLK];
	uint8_t *wire = malloc(KOF_FORM_MAX_WIRE), *sections = malloc(KOF_FORM_MAX_WIRE + 1024u);
	size_t wn, sn, rn;
	uint32_t h[KOF_MUTATION_MAX_HASH], n, j, node = 0;

	for (j = 0; j < nb; j++) {
		struct kof_form_match *m = &f->match[f->n_match];

		make_bytes(blk, seed_of(k, j));
		n = kgenome_mutation_minhash(blk, BLK, h);
		if (kof_form_add_block(f, mask, 0u, h, n) < 0)
			abort();
		memset(m, 0, sizeof *m);
		m->kind = KOF_FORM_M_SIM;
		m->thresh = 100;
		m->n = 1;
		m->arg[0] = (uint8_t)j;
		f->n_match++;
		f->n_sim++;
	}
	for (j = 0; j < nb; j++) {
		f->node[node].op = KOF_FORM_OP_LEAF;
		f->node[node].a = (uint8_t)j;
		node++;
	}
	for (j = 1; j < nb; j++) {
		f->node[node].op = KOF_FORM_OP_OR;
		f->node[node].a = j == 1u ? 0u : (uint8_t)(nb + j - 2u);
		f->node[node].b = (uint8_t)j;
		node++;
	}
	f->n_node = (uint16_t)node;
	if (kof_form_check(f)) {
		printf("  form %s does not check: %s\n", name, kof_form_check(f));
		abort();
	}
	wn = kof_form_wire_write(f, wire);
	sn = kof_form_section_write(wire, wn, sections);
	rn = record(rec, name, sections, sn);
	free(wire);
	free(sections);
	kof_form_free(f);
	return rn;
}

static __attribute__((unused)) size_t form_record(uint8_t *rec, const char *name, uint32_t k, uint32_t nb)
{
	return form_record_in(rec, name, k, nb, KOF_SCAN_ALL);
}

/* A pack of `n` records in the .kdig layout, written to <db>/<leaf>. */
static __attribute__((unused)) void write_kdig(const char *db, const char *leaf, uint8_t *const *rec, const size_t *rl, size_t n)
{
	size_t at = 8u + n * 8u, i, total = at;
	uint8_t *out;
	char path[700];

	for (i = 0; i < n; i++)
		total += rl[i];
	out = calloc(1, total);
	memcpy(out, "KDGP", 4u);
	out[4] = 1;
	put16(out, 6u, (uint16_t)n);
	for (i = 0; i < n; i++) {
		put32(out, (unsigned)(8u + i * 8u), (uint32_t)at);
		put32(out, (unsigned)(12u + i * 8u), (uint32_t)rl[i]);
		memcpy(out + at, rec[i], rl[i]);
		at += rl[i];
	}
	snprintf(path, sizeof path, "%s/%s", db, leaf);
	(void)write_file(path, out, at);
	free(out);
}


#endif /* KOFENG_TESTS_FORM_PACK_H */
