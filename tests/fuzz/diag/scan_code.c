/*
 * diag/scan_code - the same exercise as scan_bin, aimed at the CODE: the input is code bytes, and the adapter wraps them in an image
 * that always parses (the first byte picks the wrapper: ELF64 x86-64, ELF32 i386, ELF32 ARM, ELF64 AArch64, PE32+). scan_bin spends
 * most iterations on a header the parsers refuse (9 of 10 mutated images fail to parse, measured); this row reaches the sweep, the
 * wrapper analysis, the emulated run and the lineage stages with every iteration.
 *
 * The seeds are the programs of diag_seed.h (a socket and a write, a wrapper called from three places, a diamond, a retry loop, a
 * stager, a clobbering call, a stack mprotect, a value in a stack slot, syscall bytes inside an immediate) in each wrapper.
 */
#include "diag_seed.h"

/* Wrap code bytes in an image that parses: the first byte picks the wrapper. NULL when there are too few bytes or the image does not parse. */
struct diag_st *diag_wrap_code(struct fz_ctx *c, const uint8_t *in, size_t n, const uint8_t **img_out, size_t *total_out)
{
	static uint8_t img[0x2000];
	static struct ds_code code;
	static struct diag_st st;
	static struct hk_pe pe;
	unsigned kind, len;
	size_t total;

	if (n < 2)
		return NULL;
	kind = in[0] % 6u;
	len = (unsigned)(n - 1u < DS_CODE_MAX ? n - 1u : DS_CODE_MAX);
	memset(&st, 0, sizeof st);
	memcpy(code.b, in + 1, len);
	code.n = len;
	switch (kind) {
	case 5: {                                                 /* ET_REL: a relocation at the operand of each call (E8) in the code, symbols round the table */
		static const char *const syms[] = { "prepare_kernel_cred", "commit_creds", "native_write_cr0", "kmalloc", "_copy_from_user", "printk", "register_kprobe", "sys_call_table" };
		unsigned roff[16], rsym[16], nrel = 0, k;

		for (k = 0; k + 5u <= len && nrel < 16u; k++)
			if (code.b[k] == 0xe8) {
				roff[nrel] = k + 1u;
				rsym[nrel++] = (unsigned)fz_below(c->rng, 8);
			}
		total = ds_elf_rel(img, code.b, len, syms, 8, roff, rsym, nrel);
		break;
	}
	case 0: total = ds_elf64(img, &code, 0x3e); break;
	case 1: total = ds_elf32(img, &code, 3); break;
	case 2: total = ds_elf32(img, &code, 40); break;
	case 3: total = ds_elf64(img, &code, 0xb7); break;
	default:
		ds_pe(&pe, (unsigned)fz_below(c->rng, 8));
		memcpy(pe.b + pe.text_off, in + 1, len < 0x200u ? len : 0x200u);
		memcpy(img, pe.b, pe.n);
		total = pe.n;
		break;
	}
	if (kind == 4) {
		if (!kgenome_pe_image_parse(kof_buf_make(img, total), &st.pi, &st.obj))
			return NULL;
		st.obj.file_header = &st.pi;
		st.is_pe = 1;
	} else {
		if (!kgenome_elf_image_parse(kof_buf_make(img, total), &st.ei, &st.obj))
			return NULL;
		st.obj.file_header = &st.ei;
		st.is_elf = 1;
	}
	*img_out = img;
	*total_out = total;
	return &st;
}

void diag_seeds_code(struct fz_corpus *c)
{
	static struct ds_code code;
	unsigned i, k;
	uint8_t buf[DS_CODE_MAX + 1u];

	for (k = 0; k < 6; k++) {
		for (i = 0; i < DS_NPROG; i++) {
			char nm[32];

			ds_prog(&code, i);
			buf[0] = (uint8_t)k;
			memcpy(buf + 1, code.b, code.n);
			snprintf(nm, sizeof nm, "w%u-prog%u", k, i);
			fz_corpus_add(c, nm, buf, code.n + 1u);
		}
	}
}

const char *const diag_dict_code[] = { "\x0f\x05", "\xff\xd0", "\xe8", "\x48\x89\xc7", "\xb8", "\xc3", "\xcd\x80", "\x65\x48\x8b\x04\x25\x60\0\0\0", NULL };

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	const uint8_t *img;
	size_t total;
	struct diag_st *st = diag_wrap_code(c, in, n, &img, &total);

	if (!st)
		return n < 2 ? 1 : 2;
	diag_exercise(c, &st->obj, img, total);
	fz_digest(c, total);
	return 0;
}

FZ_ADAPTER(scan_code, .name = "kgenome/diag_scan_code", .covers = "", .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000,
	   .steps_base = 4000000u, .steps_per_byte = 256, .shape = FZ_REQ, .seeds = diag_seeds_code, .dict = diag_dict_code, .run = run);
