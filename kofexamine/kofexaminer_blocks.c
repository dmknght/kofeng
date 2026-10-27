#define _GNU_SOURCE

/*
 * kofexaminer_blocks.c - the similarity units (--blocks, --hashes) and the
 * shellcode-loader finder (--scfind) as the examiner prints them. Split from
 * kofexaminer.c by option, no logic changed.
 */

#include "kofexaminer_private.h"

/*
 * Everything this tool does to one object's bytes.
 *
 * Split out from examine() so the same work can be done on bytes that never were a
 * file: with --db the engine hands back what an unpacker produced, and the whole
 * point of looking at those is that they get the identical treatment - identified,
 * described, and dumped region by region. A second copy of this for children would
 * be a second thing to keep in step.
 *
 * `dir` is where a dump goes, or NULL for no dump. The caller decides it, because
 * where a child's dump belongs is a question about the tree and not about the bytes.
 */

/*
 * THE BLOCKS - what the engine cuts an object into, with every hash of each.
 *
 * `--blocks` lists the UNITS the similarity matcher reads and a block is made
 * from: the same cut the scanner makes (kof_scan_mutation_units), so what is
 * printed is what would be matched. Per unit: its region, offset, length, side
 * (the author's or the static library's), the function it is when it is one, how
 * many distinct windows it holds, and the block - the K smallest of those
 * windows, which is what a rule carries. `--hashes` adds the POOL, every distinct
 * window hash of the unit, ascending: the full set the block is a sample of, for
 * anyone comparing units of two samples to find what they share.
 *
 * Nothing here decides anything. The cut, the functions, the library and the
 * hash are the engine's; this prints them.
 *
 * A NORMALISED VIEW has no headers of its own, so its functions are its
 * parent's found again in its bytes - kgenome_funcs_remap, the same call the
 * scanner and the viewer make - and its library is already moved out.
 */
int kex_g_blocks, kex_g_hashes, kex_g_scfind;
int kex_g_decl_view;           /* the object on hand is a normalised view */
const char *kex_g_root_path;   /* the file a recovered object came from */

struct blk_ctx {
	kof_buf buf;
	const struct kof_parser *fp;
	const uint8_t *syms;
	uint32_t syms_n;
	uint32_t units;
};

static int blk_unit(void *user, uint32_t region, uint64_t off, uint64_t len,
		    uint32_t side, const struct kgenome_func *first)
{
	struct blk_ctx *c = user;
	uint32_t np = 0, k, nb, block[KGENOME_MUTATION_MINHASH_K];
	uint32_t *pool = kgenome_mutation_pool(c->buf.p + off, len, KGENOME_MUTATION_RAW, &np);
	const char *rn = (c->fp && c->fp->region_name && region != KOF_SCAN_ALL)
		       ? kof_region_label(c->fp->region_name(region)) : "ALL";
	char sym[64];

	sym[0] = 0;
	if (first && c->syms)
		kof_sym_name_at(c->syms, c->syms_n, first->value,
				     (int)first->shndx, sym, sizeof sym);
	nb = kgenome_mutation_minhash(c->buf.p + off, len, KGENOME_MUTATION_RAW, block);
	c->units++;
	printf("    unit  region=%s  off=0x%llx  len=%llu  side=%s", rn,
	       (unsigned long long)off, (unsigned long long)len,
	       side == KGENOME_MUTATION_SIDE_LIB ? "LIB" : "USER");
	if (first)
		printf("  func=%s", sym[0] ? sym : "(no symbol)");
	printf("  windows=%u", np);
	if (nb >= KGENOME_MUTATION_MIN_HASH)
		printf("  block_id=%08x\n      block", kof_mutation_fold(block, nb));
	else
		printf("  block_id=-  (under %u windows: no block)\n      block",
		       KGENOME_MUTATION_MIN_HASH);
	for (k = 0; k < nb; k++)
		printf(" %08x", block[k]);
	printf("\n");
	if (kex_g_hashes) {
		printf("      pool ");
		for (k = 0; k < np; k++)
			printf(" %08x", pool[k]);
		printf("\n");
	}
	free(pool);
	return 0;
}

void kex_print_blocks(kof_buf buf, const struct kof_obj_ctx *ctx)
{
	static struct kof_range ext[KOF_SRC_MAX_REGIONS];
	static uint8_t blk[KOF_SYM_MAX_BYTES];
	struct kgenome_func_set fs, parent;
	struct kgenome_true_all lib;
	struct blk_ctx c;
	int have_lib = 0;

	memset(&fs, 0, sizeof fs);
	memset(&parent, 0, sizeof parent);
	memset(&lib, 0, sizeof lib);
	memset(&c, 0, sizeof c);
	c.buf = buf;
	c.fp = kof_parser_of(ctx->format);
	if (kex_g_decl_view && kex_g_root_path) {
		/* The parent's functions, found again in this object's bytes. */
		FILE *f = fopen(kex_g_root_path, "rb");

		if (f) {
			long n;
			uint8_t *rb = NULL;
			struct kof_obj_ctx rctx;
			void *rview = NULL;
			const struct kof_parser *rf = NULL;

			if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) > 0 &&
			    fseek(f, 0, SEEK_SET) == 0 && (rb = malloc((size_t)n)) &&
			    fread(rb, 1, (size_t)n, f) == (size_t)n) {
				rf = kof_inspect_identify(kof_buf_make(rb, (uint64_t)n),
							  &rctx, &rview);
				if (rf && rctx.file_header) {
					struct kgenome_obj robj;

					kof_genome_obj(&rctx, &robj);
					kgenome_diag_funcs_of_view(&robj,
							       kof_buf_make(rb, (uint64_t)n),
							       NULL, buf, &fs);
				}
			}
			kof_inspect_free(rf, rview);
			free(rb);
			fclose(f);
		}
	} else if (ctx->file_header) {
		struct kgenome_obj gobj;

		kof_genome_obj(ctx, &gobj);
		kgenome_diag_funcs_of(&gobj, buf.p, buf.n, &fs);
	}
	if (!kex_g_decl_view && ctx->format == KOF_FMT_ELF && ctx->file_header) {
		kgenome_true_find_object(buf, ctx->file_header, &lib);
		have_lib = 1;
	}
	/* The names are the symbol table's, or what the engine said they are. */
	if (kex_g_decl_syms && kex_g_decl_syms_n) {
		c.syms = kex_g_decl_syms;
		c.syms_n = kex_g_decl_syms_n;
	} else {
		c.syms_n = kof_syms_build(ctx->format, buf.p, buf.n, ctx->file_header,
					  blk, sizeof blk);
		c.syms = c.syms_n ? blk : NULL;
	}
	printf("  blocks    %s%s%s  (unit = what the matcher reads; block = its %u "
	       "smallest window hashes%s)\n", kex_C_NOTE,
	       kex_g_decl_view ? "of a normalised view" : "of the object", kex_C_OFF,
	       KGENOME_MUTATION_MINHASH_K, kex_g_hashes ? "; pool = all of them" : "");
	{
		/* The size of THIS array, not the engine's usual one: the resolve is told how
		 * many ranges the buffer holds and cuts there (it used to be told 4096). */
		struct kof_ext_buf eb = kof_ext_fixed(ext, (uint32_t)(sizeof ext / sizeof ext[0]));

		const struct kof_scan_cut basis = { &fs, have_lib ? &lib : NULL,
						    kex_g_decl_fixed, kex_g_decl_fixed_n };

		kof_scan_mutation_units(ctx, buf, ~0u, &basis, &eb, blk_unit, &c);
	}
	printf("  units     %u\n", c.units);
	kgenome_funcs_free(&fs);
	kgenome_funcs_free(&parent);
}

/*
 * --scfind: where a shellcode loader keeps its payload. An analysis the examiner
 * offers on an ELF object and nothing the engine decides with - see kofscfind.h.
 * The answer is a place and the way it was found, never a verdict.
 */
void kex_print_scfind(kof_buf buf, const struct kof_obj_ctx *ctx)
{
	static struct kofscfind f;
	struct kgenome_obj gobj;
	enum kgenome_status st;

	if (ctx->format != KOF_FMT_ELF || !ctx->file_header) {
		printf("  scfind    %snot an ELF object%s\n", kex_C_NOTE, kex_C_OFF);
		return;
	}
	kof_genome_obj(ctx, &gobj);
	st = kofscfind_find(&gobj, buf.p, buf.n, &f);
	if (st != KGENOME_OK || !f.found) {
		printf("  scfind    %snone%s\n", kex_C_NOTE, kex_C_OFF);
		return;
	}
	printf("  scfind    payload at va %s0x%llx%s, offset 0x%llx, %s%llu%s bytes",
	       kex_C_SIZE, (unsigned long long)f.va, kex_C_OFF, (unsigned long long)f.at,
	       kex_C_SIZE, (unsigned long long)f.len, kex_C_OFF);
	if (f.bits)
		printf(", %u-bit syscall", f.bits);
	if (f.dec_n)
		printf(", base64 (%u bytes decoded)", f.dec_n);
	printf("\n");
}

