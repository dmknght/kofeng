/*
 * cov_pzero - the arithmetic a cure is made of (scanners/pzero.h), asserted from the contexts a cure sees.
 *
 *   kof_pz_clean_end  the end of the last region the parse claims: where an appended body begins.
 *                     No resolver, or an object that parsed into nothing, answers KGENOME_BROKEN (the
 *                     answer that stops a caller truncating on nothing); a region that runs past the object
 *                     or wraps is a hostile parse and is not a place to cut; the largest honest end wins.
 *   kof_pz_is_code    does a file offset hold instructions, asked of the parse (ELF and PE only; an offset
 *                     outside the object, a format with no code region and a context with no resolver all
 *                     say no; the first and last byte of a region are in, the byte after is out).
 *   kof_pz_unmask     the closed set of masks a virus puts over the header it saved: byte xor, word xor, add
 *                     and rotate; what each does to every byte, a short buffer, a zero length, a key that
 *                     is not a rotation, a mask that is not in the set.
 *
 * The context is a bare struct kof_obj_ctx with a fake resolver, the way scan_modctx.c does it: nothing
 * here scans a file.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include "../../libkofeng/scanners/pzero.h"
#include "../../libkofeng/scanners/scan.h"

/* a resolver that answers from a table the test fills: `all` for KOF_SCAN_ALL, `code` for bit 2 */
struct fake {
	struct kof_range all[KOF_MAX_REGIONS];
	uint32_t         n_all;
	struct kof_range code[KOF_MAX_REGIONS];
	uint32_t         n_code;
};

static struct fake fk;

static uint32_t fake_resolve(const struct kof_obj_ctx *ctx, uint32_t mask, struct kof_range *out, uint32_t cap)
{
	const struct kof_range *src = NULL;
	uint32_t n = 0, i;

	(void)ctx;
	if (mask & KOF_SCAN_ALL) {
		src = fk.all;
		n = fk.n_all;
	} else if (mask & 4u) {
		src = fk.code;
		n = fk.n_code;
	}
	for (i = 0; i < n && i < cap; i++)
		out[i] = src[i];
	return i;
}

static void ctx_of(struct kof_obj_ctx *c, uint64_t size, int fmt)
{
	memset(c, 0, sizeof *c);
	c->obj_size = size;
	c->format = (uint8_t)fmt;
	c->resolve_scan = fake_resolve;
	memset(&fk, 0, sizeof fk);
}

static void add_all(uint64_t off, uint64_t len)
{
	fk.all[fk.n_all].off = off;
	fk.all[fk.n_all].len = len;
	fk.n_all++;
}

static void add_code(uint64_t off, uint64_t len)
{
	fk.code[fk.n_code].off = off;
	fk.code[fk.n_code].len = len;
	fk.n_code++;
}

static void t_clean_end(void)
{
	struct kof_obj_ctx c;

	ctx_of(&c, 1000, KOF_FMT_ELF);
	CK(kof_pz_clean_end(NULL) == KGENOME_BROKEN, "no context");
	c.resolve_scan = NULL;
	CK(kof_pz_clean_end(&c) == KGENOME_BROKEN, "no resolver: the object was not parsed into regions");
	c.resolve_scan = fake_resolve;
	CK(kof_pz_clean_end(&c) == KGENOME_BROKEN, "a parse that claims nothing: do not truncate on nothing");

	add_all(0, 64);
	CK(kof_pz_clean_end(&c) == 64, "one region");
	add_all(64, 400);
	add_all(200, 50);                         /* inside the one before: does not move the end */
	CK(kof_pz_clean_end(&c) == 464, "the largest end of any region, in whatever order they come");
	add_all(0, 1000);
	CK(kof_pz_clean_end(&c) == 1000, "a region ending exactly at the object is honest");

	/* hostile regions: past the end, wrapping, starting past the end: skipped, not trusted */
	ctx_of(&c, 1000, KOF_FMT_PE);
	add_all(0, 300);
	add_all(900, 200);                        /* ends at 1100 > 1000 */
	add_all(2000, 10);                        /* starts past the end */
	add_all(UINT64_MAX - 5, 20);              /* off + len wraps */
	CK(kof_pz_clean_end(&c) == 300, "regions outside the object are not a place to cut (got %llu)",
	   (unsigned long long)kof_pz_clean_end(&c));
	ctx_of(&c, 1000, KOF_FMT_ELF);
	add_all(990, 20);
	add_all(5000, 1);
	CK(kof_pz_clean_end(&c) == KGENOME_BROKEN, "only hostile regions: nothing to cut at");

	/* a region of zero length at the end of the object is an end like any other */
	ctx_of(&c, 1000, KOF_FMT_ELF);
	add_all(0, 10);
	add_all(500, 0);
	CK(kof_pz_clean_end(&c) == 500, "an empty region still has an offset");
	/* the whole table: 16 regions */
	ctx_of(&c, 100000, KOF_FMT_ELF);
	{
		unsigned i;

		for (i = 0; i < KOF_MAX_REGIONS; i++)
			add_all(i * 100u, 50);
		CK(kof_pz_clean_end(&c) == (KOF_MAX_REGIONS - 1u) * 100u + 50u, "every one of the 16 is read");
	}
}

static void t_is_code(void)
{
	struct kof_obj_ctx c;

	ctx_of(&c, 1000, KOF_FMT_ELF);
	add_code(100, 50);
	add_code(400, 1);
	CK(kof_pz_is_code(&c, 100) == 1, "first byte of a code region");
	CK(kof_pz_is_code(&c, 149) == 1, "last byte of a code region");
	CK(kof_pz_is_code(&c, 150) == 0, "the byte after");
	CK(kof_pz_is_code(&c, 99) == 0, "the byte before");
	CK(kof_pz_is_code(&c, 400) == 1 && kof_pz_is_code(&c, 401) == 0, "a one byte region");
	CK(kof_pz_is_code(&c, 1000) == 0 && kof_pz_is_code(&c, UINT64_MAX) == 0, "outside the object, even if a region said so");
	/* a region that claims bytes past the object does not make them code */
	fk.code[0].off = 990;
	fk.code[0].len = 100;
	CK(kof_pz_is_code(&c, 995) == 1 && kof_pz_is_code(&c, 1000) == 0, "the object bounds the answer");
	/* the same bytes in a PE, and in a format that has no code region */
	c.format = KOF_FMT_PE;
	CK(kof_pz_is_code(&c, 995) == 1, "a PE is asked the same way");
	c.format = KOF_FMT_ZIP;
	CK(kof_pz_is_code(&c, 995) == 0, "a zip has no code region");
	c.format = KOF_FMT_ELF;
	c.resolve_scan = NULL;
	CK(kof_pz_is_code(&c, 995) == 0, "no resolver");
	CK(kof_pz_is_code(NULL, 0) == 0, "no context");
	/* no code regions at all */
	ctx_of(&c, 1000, KOF_FMT_ELF);
	CK(kof_pz_is_code(&c, 0) == 0, "an ELF with no executable segment");
}

static void t_unmask(void)
{
	uint8_t in[8] = { 0x00, 0x01, 0x7f, 0x80, 0xff, 0x12, 0x34, 0x56 }, out[16];
	uint32_t i, r;

	memset(out, 0xaa, sizeof out);
	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_NONE, 0, out, 16);
	CK(r == 8 && !memcmp(out, in, 8) && out[8] == 0xaa, "no mask: a copy, and nothing past it");

	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_XOR8, 0x5a, out, 16);
	CK(r == 8, "xor8 length");
	for (i = 0; i < 8; i++)
		CK(out[i] == (uint8_t)(in[i] ^ 0x5a), "xor8 byte %u: %02x", i, out[i]);
	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_XOR8, 0x1234u, out, 16);
	CK(r == 8 && out[0] == 0x34, "xor8 takes the low byte of the key");

	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_XOR16, 0xa1b2u, out, 16);
	CK(r == 8, "xor16 length");
	for (i = 0; i < 8; i++)
		CK(out[i] == (uint8_t)(in[i] ^ ((i & 1u) ? 0xa1 : 0xb2)), "xor16 byte %u (low byte on even offsets): %02x", i, out[i]);

	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_ADD8, 0x90, out, 16);
	CK(r == 8, "add8 length");
	for (i = 0; i < 8; i++)
		CK(out[i] == (uint8_t)(in[i] + 0x90), "add8 byte %u", i);

	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_ROL8, 3, out, 16);
	CK(r == 8, "rol8 length");
	for (i = 0; i < 8; i++)
		CK(out[i] == (uint8_t)((in[i] << 3) | (in[i] >> 5)), "rol8 byte %u", i);
	CK(kof_pz_unmask(in, 8, KOF_PZ_MASK_ROL8, 8, out, 16) == 0, "a rotate by a multiple of 8 is not a mask");
	CK(kof_pz_unmask(in, 8, KOF_PZ_MASK_ROL8, 0, out, 16) == 0, "a rotate by 0 is not a mask");
	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_ROL8, 11, out, 16);
	CK(r == 8 && out[1] == (uint8_t)((1 << 3) | (1 >> 5)), "the key is taken modulo 8");

	/* the output is bounded by the caller's room, not the input */
	memset(out, 0xaa, sizeof out);
	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_XOR8, 0xff, out, 3);
	CK(r == 3 && out[2] == (uint8_t)(in[2] ^ 0xff) && out[3] == 0xaa, "a short buffer: three bytes written, the fourth untouched");
	r = kof_pz_unmask(in, 8, KOF_PZ_MASK_NONE, 0, out, 0);
	CK(r == 0, "no room: nothing");

	/* arguments that are not a mask request */
	CK(kof_pz_unmask(NULL, 8, KOF_PZ_MASK_XOR8, 1, out, 16) == 0, "no input");
	CK(kof_pz_unmask(in, 8, KOF_PZ_MASK_XOR8, 1, NULL, 16) == 0, "no output");
	CK(kof_pz_unmask(in, 0, KOF_PZ_MASK_XOR8, 1, out, 16) == 0, "zero bytes");
	CK(kof_pz_unmask(in, 8, 99, 1, out, 16) == 0, "a mask that is not in the closed set");
	CK(kof_pz_unmask(in, 8, (uint32_t)KOF_PZ_MASK_ROL8 + 1u, 1, out, 16) == 0, "the first value past the set");
}

int main(void)
{
	t_clean_end();
	t_is_code();
	t_unmask();
	if (he_fails) {
		printf("cov_pzero: FAILED (%u of %u)\n", he_fails, he_checks);
		return 1;
	}
	printf("cov_pzero: ok (%u checks)\n", he_checks);
	return 0;
}
