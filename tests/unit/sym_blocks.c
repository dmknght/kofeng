/*
 * sym_blocks - the symbol block's writers: the pool writer (kof_symw_*), the ELF reader that fills one
 * (kof_elf_syms, kof_elf_syms_declared) and the PE's (kof_pe_syms_with, kof_pe_syms_add_room).
 *
 *   POOL WRITER   a record copied FROM another block (kof_symw_put_from) arrives with its fields and its name
 *                 and is the same record again; the writer counts what it wrote, reports what did not fit
 *   ELF           the declared count is the symbol table's, 0 for no table and for no parse; a block made with
 *                 room has every record, one made with too little has fewer AND says so in its truncation byte
 *                 (a cut table is never presented as the whole)
 *   PE            no parse and no table is an empty block, not a fault; the room an insert needs is an upper
 *                 bound of what the insert adds
 */

#include "hostile_engine.h"

#include <celllysis/trueline.h>
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../../libkofeng/analyzers/parsers/binaries/sym_pool.h"
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_sym.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"

static uint8_t blk_a[4096], blk_b[4096], big[KOF_SYM_MAX_BYTES];

static void pool_writer(void)
{
	struct kof_symw w;
	struct kof_symrec r;
	static const char *names[3] = { "alpha", "a_much_longer_symbol_name", "z" };
	uint32_t la, lb, i;
	const uint8_t *ra, *rb;

	kof_symw_begin(&w, blk_a, sizeof blk_a, 3, 0);
	for (i = 0; i < 3u; i++) {
		memset(&r, 0, sizeof r);
		r.type = (uint8_t)(i + 1u);
		r.bind = (uint8_t)(2u - i);
		r.vis = (uint8_t)i;
		r.flags = i == 1u ? KOF_SYM_F_UNDEFINED : KOF_SYM_F_DEFINED;
		r.shndx = (uint16_t)(7u + i);
		r.size = 0x1122334455667788ull + i;
		r.value = 0x8877665544332211ull - i;
		r.name = names[i];
		r.name_len = (uint32_t)strlen(names[i]);
		CK(kof_symw_put(&w, &r) == 1, "record %u fits", i);
	}
	la = kof_symw_end(&w);
	CK(kof_sym_count(blk_a, la) == 3u && blk_a[KOF_SYM_H_TRUNC] == 0, "a block of three, whole");

	/* the same three, each copied out of the first block into a second one */
	kof_symw_begin(&w, blk_b, sizeof blk_b, 3, 0);
	for (i = 0; i < 3u; i++) {
		const uint8_t *src = kof_sym_rec(blk_a, la, i);

		CK(src && kof_symw_put_from(&w, blk_a, la, src) == 1, "record %u copied from the first block", i);
	}
	lb = kof_symw_end(&w);
	CK(lb == la && kof_sym_count(blk_b, lb) == 3u, "the copy is the same size and count (%u, %u)", lb, la);
	for (i = 0; i < 3u; i++) {
		uint32_t na = 0, nb = 0;
		const char *sa, *sb;

		ra = kof_sym_rec(blk_a, la, i);
		rb = kof_sym_rec(blk_b, lb, i);
		sa = ra ? kof_sym_name(blk_a, la, ra, &na) : NULL;
		sb = rb ? kof_sym_name(blk_b, lb, rb, &nb) : NULL;
		CK(ra && rb && sa && sb && na == nb && !memcmp(sa, sb, na) && !strcmp(sb, names[i]), "record %u: the name arrives through the pool (%s)", i, sb ? sb : "NULL");
		CK(ra && rb && ra[KOF_SYM_R_TYPE] == rb[KOF_SYM_R_TYPE] && ra[KOF_SYM_R_BIND] == rb[KOF_SYM_R_BIND] &&
		   ra[KOF_SYM_R_VIS] == rb[KOF_SYM_R_VIS] && ra[KOF_SYM_R_FLAGS] == rb[KOF_SYM_R_FLAGS] &&
		   kof_sym_u16(ra, KOF_SYM_R_SHNDX) == kof_sym_u16(rb, KOF_SYM_R_SHNDX) &&
		   kof_sym_u64(ra, KOF_SYM_R_SIZE) == kof_sym_u64(rb, KOF_SYM_R_SIZE) &&
		   kof_sym_u64(ra, KOF_SYM_R_VALUE) == kof_sym_u64(rb, KOF_SYM_R_VALUE), "record %u: every field is the same", i);
	}
	CK(!memcmp(blk_a, blk_b, la), "and the two blocks are byte for byte one block");

	/* a block with room for one record: the second put says it did not fit */
	kof_symw_begin(&w, blk_b, KOF_SYM_HDRLEN + KOF_SYM_RECLEN + 16u, 1, 16);   /* a name takes its bytes, a NUL and a key */
	{
		const uint8_t *s0 = kof_sym_rec(blk_a, la, 0), *s1 = kof_sym_rec(blk_a, la, 1);
		int p0 = kof_symw_put_from(&w, blk_a, la, s0), p1 = kof_symw_put_from(&w, blk_a, la, s1);
		uint32_t l = kof_symw_end(&w);

		CK(p0 == 1 && p1 == 0 && w.trunc && kof_sym_count(blk_b, l) == 1u && blk_b[KOF_SYM_H_TRUNC] != 0,
		   "a table with room for one: the second is refused, the block is marked cut, and holds one");
	}
}

/*
 * KOF_SYM_ABS_MAX_RECS / KOF_SYM_ABS_MAX_POOL: the writer never plans more records than a 16 bit index can name
 * (65534: 0xffff is "none"), nor more pool than 8 MiB, whatever room it is handed - the cap is a bound on the
 * block, and the room beyond it is simply not used.
 */
static void abs_limits(void)
{
	struct kof_symw w;
	size_t cap = (size_t)64 << 20;
	uint8_t *big_buf = malloc(cap);

	CK(KOF_SYM_ABS_MAX_RECS == 65534u && KOF_SYM_ABS_MAX_RECS < KOF_SYM_NO_START && KOF_SYM_ABS_MAX_POOL == (8u << 20),
	   "the absolute bounds: 65534 records (below the 'none' index), 8 MiB of pool");
	CK(KOF_SYM_ABS_MAX_BYTES == KOF_SYM_HDRLEN + KOF_SYM_ABS_MAX_RECS * KOF_SYM_RECLEN + KOF_SYM_ABS_MAX_POOL, "and the largest block is exactly those");
	CK(big_buf != NULL, "room to offer");
	if (!big_buf)
		return;
	kof_symw_begin(&w, big_buf, (uint32_t)cap, 0, 0);
	CK(w.rec_cap == KOF_SYM_ABS_MAX_RECS, "64 MiB of room plans %u records, not what it could hold (%u)", KOF_SYM_ABS_MAX_RECS, w.rec_cap);
	kof_symw_begin(&w, big_buf, (uint32_t)cap, 100000u, 1000u);
	CK(w.rec_cap == KOF_SYM_ABS_MAX_RECS && w.pool_cap <= KOF_SYM_ABS_MAX_POOL,
	   "asking for 100000 records still plans 65534, and the pool stops at 8 MiB (%u)", w.pool_cap);
	kof_symw_begin(&w, big_buf, (uint32_t)(KOF_SYM_HDRLEN + 10u * KOF_SYM_RECLEN), 0, 0);
	CK(w.rec_cap < 10u, "a small buffer plans fewer records than it has room for, the pool taking its share (%u)", w.rec_cap);
	free(big_buf);
}

static uint8_t *slurp_file(const char *path, uint64_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p;
	long sz;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	p = sz > 0 ? malloc((size_t)sz) : NULL;
	if (p && fread(p, 1, (size_t)sz, f) != (size_t)sz) {
		free(p);
		p = NULL;
	}
	fclose(f);
	*n = p ? (uint64_t)sz : 0;
	return p;
}

static void elf(const char *path)
{
	uint64_t n = 0;
	uint8_t *b = slurp_file(path, &n);
	struct kgenome_elf_info e;
	struct kof_obj_ctx ctx;
	kof_buf f;
	uint32_t decl, len, cnt, len2;
	static uint8_t small[KOF_SYM_HDRLEN + 4u * KOF_SYM_RECLEN + 64u];

	CK(b != NULL, "fixture %s", path);
	if (!b)
		return;
	memset(&e, 0, sizeof e);
	memset(&ctx, 0, sizeof ctx);
	f = kof_buf_make(b, n);
	CK(kof_elf_parse(f, &e, &ctx) == 1, "the fixture parses");
	decl = kof_elf_syms_declared(f, &e);
	len = kof_elf_syms(f, &e, big, sizeof big);
	cnt = kof_sym_count(big, len);
	printf("  %s: %u declared, block of %u bytes with %u records\n", path, decl, len, cnt);
	CK(decl > 4u, "the fixture declares symbols (%u)", decl);
	CK(len >= KOF_SYM_HDRLEN && !memcmp(big, "KSYM", 4) && cnt > 0u && cnt <= decl, "a block with a header and records, never more than declared");
	CK(big[KOF_SYM_H_TRUNC] == 0 || decl > KOF_SYM_MAX_RECS, "made with room, it is whole");
	len2 = kof_elf_syms(f, &e, small, sizeof small);
	CK(len2 >= KOF_SYM_HDRLEN && len2 <= sizeof small && kof_sym_count(small, len2) < cnt && kof_sym_count(small, len2) <= 4u,
	   "made with room for four records it holds at most four (%u)", kof_sym_count(small, len2));
	CK(small[KOF_SYM_H_TRUNC] != 0, "and says it was cut: a short table is never presented as the whole");
	CK(kof_elf_syms(f, &e, small, KOF_SYM_HDRLEN - 1u) == 0, "a buffer under the header's size gets nothing");

	/* no parse, no symbols */
	CK(kof_elf_syms_declared(f, NULL) == 0u, "declared: no parse is 0");
	memset(&e, 0, sizeof e);
	CK(kof_elf_syms_declared(f, &e) == 0u, "declared: a view that is not valid is 0");
	CK(kof_elf_syms_declared(kof_buf_make(b, 16), &e) == 0u, "declared: nothing to read is 0");
	len = kof_elf_syms(kof_buf_make(NULL, 0), NULL, small, sizeof small);
	CK(len == 0u || (len >= KOF_SYM_HDRLEN && kof_sym_count(small, len) == 0u), "the symbol block of nothing: nothing, or an empty block");
	free(b);
}

static void pe(void)
{
	static const char *dll[3] = { "KERNEL32.dll", "user32.dll", "a_dll_with_a_name_that_is_rather_long_for_the_table.dll" };
	static const char *fn[3] = { "VirtualAlloc", "MessageBoxA", "f" };
	uint32_t room, len, added;
	kof_buf none = kof_buf_make(NULL, 0);

	CK(kof_pe_syms_add_room(dll, fn, 0) == 0u, "no imports need no room");
	room = kof_pe_syms_add_room(dll, fn, 3);
	CK(room >= 3u * (KOF_SYM_RECLEN + KOF_SYM_KEYLEN) + 3u && room > kof_pe_syms_add_room(dll, fn, 2) && kof_pe_syms_add_room(dll, fn, 2) > kof_pe_syms_add_room(dll, fn, 1),
	   "room grows with each import and holds a record and a name for each (%u)", room);

	len = kof_pe_syms_with(none, NULL, NULL, blk_a, sizeof blk_a);
	CK(len == 0u || (len >= KOF_SYM_HDRLEN && kof_sym_count(blk_a, len) == 0u), "no parse, no table: nothing or an empty block (%u)", len);
	{
		struct kof_symw w;

		kof_symw_begin(&w, blk_a, sizeof blk_a, 0, 0);
		len = kof_symw_end(&w);
		added = kof_pe_syms_add_imports(blk_a, len, sizeof blk_a, dll, fn, 3);
		CK(added > len && added <= len + room && kof_sym_count(blk_a, added) == 3u,
		   "three imports added to an empty block: three records, and no more bytes than the room said (%u of %u)", added - len, room);
		CK(kof_pe_syms_add_imports(blk_a, added, added + 4u, dll, fn, 3) == added && (blk_a[KOF_SYM_H_TRUNC] & KOF_SYM_TRUNC_ROOM),
		   "a buffer without that room: the block is untouched and marked cut for lack of room");
	}
}

int main(int argc, char **argv)
{
	pool_writer();
	abs_limits();
	elf(argc > 1 ? argv[1] : "build/test/fixtures/shared-elf64.so");
	pe();
	printf("sym_blocks: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
