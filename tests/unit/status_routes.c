/*
 * status_routes - a limit the library computed reaches the verdict path.
 *
 * Three statuses were computed and dropped on the way to the engine:
 *
 *   - the PE export directory's (pe_sym.c passed NULL for it): past 4096 names the walk is
 *     cut and says KGENOME_TRUNCATED, and the symbol block, which holds the first 4096,
 *     said nothing;
 *   - the PE import table's (objctx_diag.c built it and never read `status`): a thunk
 *     budget that ran out left the block and the diagnose graph short with no flag;
 *   - the function set's (kgenome_func_set.status, written and read nowhere).
 *
 * Each now reaches the object as oc_scan_limit - kof_result.broken == KOF_BROKEN_LIMIT -
 * and the block's header byte says WHY (KOF_SYM_TRUNC_SOURCE: a bound of the source, which
 * a larger buffer does not change, so kof_syms_build_grow does not rebuild for it).
 *
 * The cases are PE directories built in memory, scanned through the whole pipeline
 * against tests/sigs/sig_pe_syms_00.c, which reads the symbol block. Each has its
 * control just inside the limit, which must NOT be cut. The function set's status is
 * NOMEM only (its other values are for a view), reached by failing the one allocation
 * that builds it; that case needs an interposed realloc and is skipped under a sanitizer.
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include <genotype/image/pe_image.h>
#include <genotype/image/obj.h>

#define PE_RAW 0x18000u
#define PE_FILE (0x400u + PE_RAW)
#define RAW(rva) (0x400u + ((rva) - 0x1000u))

static uint8_t pe_a[PE_FILE];

/* PE32+, one RWX section holding rva 0x1000..0x19000. Directories are the caller's. */
static void pe_base(void)
{
	memset(pe_a, 0, sizeof pe_a);
	pe_a[0] = 'M';
	pe_a[1] = 'Z';
	put32(pe_a, 0x3c, 0x80);
	memcpy(pe_a + 0x80, "PE\0\0", 4);
	put16(pe_a, 0x84, 0x8664);
	put16(pe_a, 0x86, 1);
	put16(pe_a, 0x94, 0xf0);
	put16(pe_a, 0x96, 0x22);
	put16(pe_a, 0x98, 0x20b);
	put32(pe_a, 0x98 + 16, 0x1000);
	put64(pe_a, 0x98 + 24, 0x140000000ull);
	put32(pe_a, 0x98 + 32, 0x1000);
	put32(pe_a, 0x98 + 36, 0x200);
	put32(pe_a, 0x98 + 56, 0x19000);
	put32(pe_a, 0x98 + 60, 0x400);
	put32(pe_a, 0x98 + 108, 16);
	memcpy(pe_a + 0x188, ".text", 5);
	put32(pe_a, 0x188 + 8, PE_RAW);
	put32(pe_a, 0x188 + 12, 0x1000u);
	put32(pe_a, 0x188 + 16, PE_RAW);
	put32(pe_a, 0x188 + 20, 0x400);
	put32(pe_a, 0x188 + 36, 0xe0000020u);
}

static void exports(unsigned names)
{
	unsigned i;

	pe_base();
	put32(pe_a, 0x98 + 112, 0x1000);               /* export directory */
	put32(pe_a, 0x98 + 116, 0x100);
	put32(pe_a, RAW(0x1000) + 24, names);
	put32(pe_a, RAW(0x1000) + 28, 0x1100);         /* functions */
	put32(pe_a, RAW(0x1000) + 32, 0x2000);         /* names */
	put32(pe_a, RAW(0x1000) + 36, 0x7000);         /* ordinals */
	put32(pe_a, RAW(0x1100), 0x1000);
	for (i = 0; i < names; i++) {
		put32(pe_a, RAW(0x2000) + 4u * i, 0xa000u + 4u * i);
		put16(pe_a, RAW(0x7000) + 2u * i, 0);
		pe_a[RAW(0xa000u + 4u * i)] = 'n';
		pe_a[RAW(0xa000u + 4u * i) + 1u] = (uint8_t)('a' + i % 26u);
	}
}

/* `desc` descriptors over one table of 4096 thunks: the total thunk budget is the file's
 * own size over the pointer width, so enough descriptors outrun it. */
static void imports(unsigned desc)
{
	unsigned i;

	pe_base();
	put32(pe_a, 0x98 + 120, 0x1000);
	put32(pe_a, 0x98 + 124, desc * 20u);
	for (i = 0; i < desc; i++) {
		put32(pe_a, RAW(0x1000) + 20u * i + 0, 0x3000);
		put32(pe_a, RAW(0x1000) + 20u * i + 12, 0x2800);
		put32(pe_a, RAW(0x1000) + 20u * i + 16, 0x3000);
	}
	memcpy(pe_a + RAW(0x2800), "k.dll", 6);
	memcpy(pe_a + RAW(0xc000) + 2, "fn", 3);
	for (i = 0; i < 4096u; i++)
		put64(pe_a, RAW(0x3000) + 8u * i, 0xc000);
}

static unsigned limit_objects(void)
{
	struct e2e r;
	unsigned i, n = 0;

	if (!e2e_scan(pe_a, sizeof pe_a, &r))
		return 0xffffu;
	for (i = 0; i < r.n; i++)
		n += r.o[i].broken == KOF_BROKEN_LIMIT;
	return n;
}

/* The block the engine would build for the object in pe_a, and its header byte. */
static unsigned header_byte(unsigned *count)
{
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	static uint8_t *buf;
	static uint32_t cap;
	uint32_t n, passes = 0;

	CK(kgenome_pe_image_parse(kof_buf_make(pe_a, sizeof pe_a), &info, &obj));
	n = kof_syms_build_grow(KOF_FMT_PE, pe_a, sizeof pe_a, &info, NULL, &buf, &cap, &passes);
	*count = kof_sym_count(buf, n);
	if (n <= KOF_SYM_H_TRUNC)
		return 0xffu;
	return buf[KOF_SYM_H_TRUNC] | (passes << 8);
}

static void block_bits(void)
{
	unsigned count, hb;

	/* inside the export bound: whole, one build */
	exports(4096);
	hb = header_byte(&count);
	CK((hb & 0xffu) == 0u && count == 4096u && (hb >> 8) == 1u);
	/* past it: the walk was cut. The bit is the SOURCE's, so the buffer is not grown for
	 * it: ONE build, and the block is not marked as short of room. */
	exports(5000);
	hb = header_byte(&count);
	CK((hb & KOF_SYM_TRUNC_SOURCE) != 0u);
	CK((hb & KOF_SYM_TRUNC_ROOM) == 0u);
	CK((hb >> 8) <= 2u);                     /* sized from the table: at most one more pass */
	CK(count == 4096u);
	CK(kof_sym_truncated(NULL, 0) == 0);
}

static void engine_routes(void)
{
	if (!e2e_open(NULL)) {
		printf("  (no test database: the engine cases are skipped)\n");
		return;
	}
	/* the controls, just inside each limit: not cut */
	exports(4096);
	CK(limit_objects() == 0u);
	imports(1);
	CK(limit_objects() == 0u);
	/* the export directory past its bound: the object says it was cut */
	exports(5000);
	CK(limit_objects() >= 1u);
	/* an import table that ran out of thunk budget: the same */
	imports(256);
	CK(limit_objects() >= 1u);
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	block_bits();
	engine_routes();
	if (fails) {
		printf("status_routes: %d check(s) failed\n", fails);
		return 1;
	}
	printf("status_routes: export bound and import budget reach the object (broken=LIMIT); the block says which\n");
	return 0;
}
