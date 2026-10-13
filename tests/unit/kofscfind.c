/*
 * kofscfind - where a shellcode loader keeps its payload, the examiner's analysis.
 *
 * kofscfind_run is the one search and kofscfind_find the whole analysis, with the
 * tool's own sweep. This builds loaders in memory, byte for byte, and checks the
 * answer both ways: the search on its own (with the sweep answered by the test,
 * so each gate is exercised alone) and the whole analysis (the real sweep over
 * the real code), and the image the viewer derives from the answer.
 *
 * EVERY EXPECTATION IS THE CORRECT BEHAVIOUR. The controls are the shapes that
 * must NOT be found, each differing from a loader in exactly one thing: the
 * variable is only read, the file has no PT_INTERP (a library), the blob is a
 * table, the file is mostly code.
 */

#include "caps_fix.h"
#include <celllysis/celllysis.h>
#include <celllysis/xref.h>
#include "../../kofexamine/kofscfind.h"

#define TEXT_VA   0x400100ull
#define BLOB_N    128u

enum shape {
	INLINE_CALLED,        /* the blob is a global array, and the code calls it    */
	INLINE_READ,          /* ... and the code only reads it                       */
	INLINE_LIBRARY,       /* ... in a file with no PT_INTERP                      */
	INLINE_TABLE,         /* ... and the blob is one repeated byte                */
	INLINE_BIGCODE,       /* ... in a file that is mostly code                    */
	INLINE_BASE64,        /* the blob is base64 text and the code calls it        */
	POINTER_CALLED        /* the global is a pointer to a clear blob in .rodata   */
};

static uint8_t img[1u << 16];

static uint32_t lcg(uint32_t *s)
{
	*s = *s * 1664525u + 1013904223u;
	return *s >> 16;
}

static void sec_hdr(uint8_t *h, uint32_t name, uint32_t type, uint64_t flags,
		    uint64_t addr, uint64_t off, uint64_t size, uint32_t link,
		    uint32_t info, uint64_t esz)
{
	put32(h, 0, name);
	put32(h, 4, type);
	put64(h, 8, flags);
	put64(h, 16, addr);
	put64(h, 24, off);
	put64(h, 32, size);
	put32(h, 40, link);
	put32(h, 44, info);
	put64(h, 48, 1);
	put64(h, 56, esz);
}

/*
 * An x86-64 ELF with PT_INTERP, a .text of a few instructions and a global the
 * code treats in the way `shape` says. Returns the length.
 */
static uint64_t build(uint8_t *b, enum shape shape)
{
	static const char shs[] = "\0.text\0.rodata\0.data\0.symtab\0.strtab\0.shstrtab\0";
	static const char str[] = "\0_start\0payload\0";
	const uint64_t text_off = 0x100, ro_off = 0x180, data_off = 0x400;
	uint64_t var_va, var_n, sym_off, str_off, shstr_off, sh_off, len;
	uint32_t seed = 0x1234567u, i, code_n = 0;
	int ptr = shape == POINTER_CALLED, interp = shape != INLINE_LIBRARY;
	uint8_t *c = b + text_off;

	memset(b, 0, 0x2000);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 0x3e);
	put32(b, 20, 1);
	put64(b, 24, TEXT_VA);
	put64(b, 32, 64);
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 2);
	put16(b, 58, 64);
	/* program header 0: PT_INTERP (or PT_NOTE for the library), 1: one RWX PT_LOAD */
	put32(b, 64, interp ? 3u : 4u);
	put64(b, 64 + 8, 0xb0);
	put64(b, 64 + 32, 12);
	put32(b, 64 + 56, 1);
	put32(b, 64 + 56 + 4, 7);
	put64(b, 64 + 56 + 16, 0x400000);
	put64(b, 64 + 56 + 32, 0x2000);
	put64(b, 64 + 56 + 40, 0x2000);
	memcpy(b + 0xb0, "/lib/ld.so", 11);

	/* the data: the blob, or the pointer to it */
	if (ptr) {
		/* a clear blob in .rodata that makes a syscall, and a pointer to it */
		for (i = 0; i < 64u; i++)
			b[ro_off + i] = (uint8_t)(1u + lcg(&seed) % 254u);
		b[ro_off + 20] = 0x0f;
		b[ro_off + 21] = 0x05;
		b[ro_off + 64] = 0;
		put64(b, (unsigned)data_off, 0x400000ull + ro_off);
		var_n = 8;
	} else {
		for (i = 0; i < BLOB_N; i++)
			b[data_off + i] = shape == INLINE_TABLE ? 0x41
				: (uint8_t)(1u + lcg(&seed) % 254u);
		if (shape == INLINE_BASE64) {
			static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

			for (i = 0; i < BLOB_N; i++)
				b[data_off + i] = (uint8_t)a[lcg(&seed) % 64u];
		}
		var_n = BLOB_N;
	}
	var_va = 0x400000ull + data_off;

	/* the code: lea/mov rax,[rip+var]; call rax; ret - or a read and a ret */
	{
		uint64_t rip = TEXT_VA + 7u;
		int32_t rel = (int32_t)(var_va - rip);

		if (shape == INLINE_READ || shape == INLINE_LIBRARY) {
			/* mov eax,[rip+rel]; ret : the variable is read and nothing more */
			c[code_n++] = 0x8b; c[code_n++] = 0x05;
			put32(c, code_n, (uint32_t)(int32_t)(var_va - (TEXT_VA + 6u)));
			code_n += 4;
			c[code_n++] = 0xc3;
		} else {
			c[code_n++] = 0x48;
			c[code_n++] = ptr ? 0x8b : 0x8d;
			c[code_n++] = 0x05;
			put32(c, code_n, (uint32_t)rel);
			code_n += 4;
			c[code_n++] = 0xff; c[code_n++] = 0xd0;     /* call rax */
			c[code_n++] = 0xc3;
		}
		if (shape == INLINE_BIGCODE)
			code_n = 9000;              /* a program, not a loader */
	}

	sym_off = (data_off + var_n + 16u + 7u) & ~7ull;
	str_off = sym_off + 3u * 24u;
	shstr_off = str_off + sizeof str;
	sh_off = (shstr_off + sizeof shs + 7u) & ~7ull;
	memset(b + sym_off, 0, 3u * 24u);
	put32(b + sym_off + 24, 0, 1);                       /* _start */
	b[sym_off + 24 + 4] = 0x12;
	put16(b + sym_off + 24, 6, 1);
	put64(b + sym_off + 24, 8, TEXT_VA);
	put64(b + sym_off + 24, 16, code_n);
	put32(b + sym_off + 48, 0, 8);                       /* payload */
	b[sym_off + 48 + 4] = 0x11;                          /* GLOBAL OBJECT */
	put16(b + sym_off + 48, 6, 3);                       /* .data */
	put64(b + sym_off + 48, 8, var_va);
	put64(b + sym_off + 48, 16, var_n);
	memcpy(b + str_off, str, sizeof str);
	memcpy(b + shstr_off, shs, sizeof shs);

	memset(b + sh_off, 0, 7u * 64u);
	sec_hdr(b + sh_off + 64, 1, 1, 6, TEXT_VA, text_off, code_n, 0, 0, 0);
	sec_hdr(b + sh_off + 128, 7, 1, 2, 0x400000ull + ro_off, ro_off, 0x80, 0, 0, 0);
	sec_hdr(b + sh_off + 192, 15, 1, 3, var_va, data_off, var_n, 0, 0, 0);
	sec_hdr(b + sh_off + 256, 21, 2, 0, 0, sym_off, 3u * 24u, 5, 1, 24);
	sec_hdr(b + sh_off + 320, 29, 3, 0, 0, str_off, sizeof str, 0, 0, 0);
	sec_hdr(b + sh_off + 384, 37, 3, 0, 0, shstr_off, sizeof shs, 0, 0, 0);
	put64(b, 40, sh_off);
	put16(b, 60, 7);
	put16(b, 62, 6);
	len = sh_off + 7u * 64u;
	if (shape == INLINE_BIGCODE)
		len = len;      /* the code is claimed bigger than it is: the section says it */
	return len;
}

/* ---- the lib on its own: the sweep is the test's answer ---------------------- */

static uint32_t xref_answer;

static uint32_t sweep(void *user, uint64_t va, uint64_t size)
{
	(void)user; (void)va; (void)size;
	return xref_answer;
}

static int run_with(uint64_t len, uint32_t xref, struct kofscfind *out)
{
	struct kof_obj_ctx ctx;
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf = kof_buf_make(img, len);
	struct kofscfind_in in;
	struct kgenome_obj gobj;
	static uint8_t view[1u << 16];
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	CK(ok);
	kof_genome_obj(&ctx, &gobj);
	memset(&in, 0, sizeof in);
	in.obj = &gobj;
	in.data = img;
	in.n = len;
	in.xref = sweep;
	xref_answer = xref;
	return kofscfind_run(&in, out) == KGENOME_OK;
}

static void run_tests(void)
{
	static struct kofscfind f;
	uint64_t len;

	len = build(img, INLINE_CALLED);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(f.found);
	CK(f.len == BLOB_N);
	CK(f.va == 0x400400ull);
	CK(f.at == 0x400);
	CK(f.bits == 0 && f.dec_n == 0);

	/* The same file, and the code only reads the variable: not a payload. */
	CK(run_with(len, KGENOME_XREF_READ, &f));
	CK(!f.found);
	/* Staged - the argument of a call in the region of an indirect call. */
	CK(run_with(len, KGENOME_XREF_ARG | KGENOME_XREF_RGN_ICALL, &f));
	CK(f.found);
	/* An argument alone is not enough: the control reads a table into a call. */
	CK(run_with(len, KGENOME_XREF_ARG, &f));
	CK(!f.found);
	/* No sweep for this architecture says "not analysed", and the byte tests decide. */
	CK(run_with(len, KGENOME_XREF_PARTIAL, &f));
	CK(f.found);

	len = build(img, INLINE_LIBRARY);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(!f.found);                           /* no PT_INTERP: a library of tables */

	len = build(img, INLINE_TABLE);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(!f.found);                           /* one byte owns the blob */

	len = build(img, INLINE_BIGCODE);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(!f.found);                           /* a program, not a loader */

	len = build(img, INLINE_BASE64);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(f.found);
	CK(f.len == BLOB_N);
	CK(f.dec_n == BLOB_N * 3u / 4u);        /* what `at` decodes to is in dec */

	len = build(img, POINTER_CALLED);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(f.found);
	CK(f.at == 0x180);                      /* the blob, not the pointer */
	CK(f.va == 0x400180ull);
	CK(f.len == 64);
	CK(f.bits == 64);                       /* `syscall` */

	/* Not an ELF at all: a status, and nothing found. */
	{
		struct kofscfind_in in;
		struct kgenome_obj gobj;

		memset(&gobj, 0, sizeof gobj);
		memset(&in, 0, sizeof in);
		in.obj = &gobj;
		in.data = img;
		in.n = len;
		CK(kofscfind_run(&in, &f) == KGENOME_UNSUPPORTED);
		CK(!f.found);
	}
}

/* ---- the whole analysis: the sweep is the tool's own ------------------------- */

static int find_run(uint64_t len, struct kofscfind *out)
{
	struct kof_obj_ctx ctx;
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf = kof_buf_make(img, len);
	struct kgenome_obj gobj;
	static uint8_t view[1u << 16];
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	CK(ok);
	kof_genome_obj(&ctx, &gobj);
	return kofscfind_find(&gobj, img, len, out) == KGENOME_OK;
}

static void find_tests(void)
{
	static struct kofscfind f;
	uint64_t len;

	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f));
	CK(f.found && f.len == BLOB_N && f.va == 0x400400ull);

	len = build(img, INLINE_BASE64);
	CK(find_run(len, &f));
	CK(f.found && f.dec_n == BLOB_N * 3u / 4u);

	len = build(img, POINTER_CALLED);
	CK(find_run(len, &f));
	CK(f.found && f.at == 0x180 && f.bits == 64);

	/* the controls: read only, and not a program */
	len = build(img, INLINE_READ);
	CK(find_run(len, &f));
	CK(!f.found);
	len = build(img, INLINE_LIBRARY);
	CK(find_run(len, &f));
	CK(!f.found);
	len = build(img, INLINE_BIGCODE);
	CK(find_run(len, &f));
	CK(!f.found);
}


/* ---- the payload as an object (what the viewer derives from the answer) ------ */

/* Parses `n` bytes of `b` as the viewer would an object it was handed, and
 * returns the ELF parse, or NULL. */
static const struct kgenome_elf_info *parse_img(const uint8_t *b, uint64_t n,
						struct kgenome_obj *gobj)
{
	static struct kof_obj_ctx ctx;
	static uint8_t view[1u << 16];
	const struct kof_parser *pl;
	kof_buf buf = kof_buf_make(b, n);
	uint32_t np, i;
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	if (!ok)
		return NULL;
	kof_genome_obj(&ctx, gobj);
	return kgenome_obj_elf(gobj);
}

static void image_tests(void)
{
	static struct kofscfind f;
	static uint8_t out[KOFSCFIND_IMAGE_MAX];
	struct kgenome_obj gobj;
	const struct kgenome_elf_info *e;
	uint64_t len, n;

	/* An inline blob: the image is a header and the blob's own bytes. */
	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f));
	CK(f.found);
	n = kofscfind_image(&f, img, len, 1, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + BLOB_N);
	CK(!memcmp(out + KOFSCFIND_HDR_ROOM, img + 0x400, BLOB_N));
	e = parse_img(out, n, &gobj);
	CK(e && e->valid);
	CK(e && e->seg_count == 1 && e->sec_count == 0);
	CK(gobj.arch == KGENOME_ARCH_X86_64);

	/* The parent's width is the default where the payload did not say. */
	n = kofscfind_image(&f, img, len, 0, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + BLOB_N);
	e = parse_img(out, n, &gobj);
	CK(e && e->valid && gobj.arch == KGENOME_ARCH_X86);

	/* Base64 text: the image carries what it decodes to, not the text. */
	len = build(img, INLINE_BASE64);
	CK(find_run(len, &f));
	CK(f.found && f.dec_n);
	n = kofscfind_image(&f, img, len, 1, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + f.dec_n);
	CK(!memcmp(out + KOFSCFIND_HDR_ROOM, f.dec, f.dec_n));

	/* A pointer-shaped loader: the blob in .rodata, and a syscall that says
	 * it is 64-bit even when the caller's default is 32. */
	len = build(img, POINTER_CALLED);
	CK(find_run(len, &f));
	CK(f.found && f.bits == 64);
	n = kofscfind_image(&f, img, len, 0, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + 64u);
	CK(!memcmp(out + KOFSCFIND_HDR_ROOM, img + 0x180, 64));
	e = parse_img(out, n, &gobj);
	CK(e && e->valid && gobj.arch == KGENOME_ARCH_X86_64);
	/* and the other way round: 32 from the payload beats a 64-bit parent */
	f.bits = 32;
	n = kofscfind_image(&f, img, len, 1, out, sizeof out);
	e = parse_img(out, n, &gobj);
	CK(n && e && e->valid && gobj.arch == KGENOME_ARCH_X86);

	/* The refusals: nothing found, no room, a range outside the object. */
	len = build(img, INLINE_READ);
	CK(find_run(len, &f));
	CK(!f.found);
	CK(kofscfind_image(&f, img, len, 1, out, sizeof out) == 0);
	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f));
	CK(kofscfind_image(&f, img, len, 1, out, KOFSCFIND_HDR_ROOM) == 0);
	CK(kofscfind_image(&f, img, f.at + 4u, 1, out, sizeof out) == 0);
	CK(kofscfind_image(NULL, img, len, 1, out, sizeof out) == 0);
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	run_tests();
	find_tests();
	image_tests();
	printf("kofscfind: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
