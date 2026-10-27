/*
 * diag/scan_lineage - the same exercise as scan_bin, seeded with the programs the lineage tests generate (tests/lib/genome/lineage_ir.h,
 * _cg.h, _img.h): a random program of calls, loops, indirect calls, tail jumps and memory, compiled to a dynamically linked ELF64, an i386
 * ELF, a PE32+ and a PE32, with a lazy PLT, an IBT PLT, `-fno-plt` slots, a thunk table and a symbol table for half of them. These are the
 * images the dynamic-import route (diag_elfimp.c), the PE import route (diag_pe.c), the wrapper analysis and the lineage stages were
 * written for; the hand-assembled seeds of scan_bin do not have an import table.
 *
 * The field map is the ELF / PE header's own (the program header, the section headers and the dynamic table are reached by the
 * structure-aware mutators through the record table), the checks are scan_bin's.
 */
#include "../../lib/genome/lineage_img.h"

#include "diag_seed.h"

static struct lg_img G;
static struct lg_cg C;
static struct lg_prog P;

#define LG_NSEEDS_MAX 24u

static struct fz_field fld[LG_NSEEDS_MAX][8];
static struct fz_map map[LG_NSEEDS_MAX];

static void seeds(struct fz_corpus *c)
{
	unsigned target, i, made = 0;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++)
		for (i = 0; made < (target + 1u) * (LG_NSEEDS_MAX / 4u) && i < 60u; i++) {
			struct lg_rng r;
			struct fz_map *m = &map[made];
			struct fz_field *f = fld[made];
			char name[32];
			unsigned k = 0;

			r.s = ((uint64_t)i * 7919u + (uint64_t)target * 104729u + 77u) * 0x9e3779b97f4a7c15ull + 1u;
			lg_generate(&P, &r, LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_DEAD | LG_F_MEM);
			if (P.bad || !lg_codegen(&C, &P, &r, (int)target) || !lg_build(&G, &C, &r, (int)lg_rnd(&r, 2u)))
				continue;
			if (G.n > 9000u)
				continue;                         /* the mutators and the walk are per byte: small seeds */
			m->f = f;
			if (target <= LG_T_ELF32) {
				const int wide = target == LG_T_ELF64;

				f[k].off = 24u; f[k].size = wide ? 8u : 4u; f[k].be = 0; f[k++].kind = FZ_RVA;       /* e_entry */
				f[k].off = wide ? 32u : 28u; f[k].size = wide ? 8u : 4u; f[k].be = 0; f[k++].kind = FZ_OFFSET;    /* e_phoff */
				f[k].off = wide ? 40u : 32u; f[k].size = wide ? 8u : 4u; f[k].be = 0; f[k++].kind = FZ_OFFSET;    /* e_shoff */
				f[k].off = wide ? 56u : 44u; f[k].size = 2; f[k].be = 0; f[k++].kind = FZ_COUNT;                  /* e_phnum */
				f[k].off = wide ? 60u : 48u; f[k].size = 2; f[k].be = 0; f[k++].kind = FZ_COUNT;                  /* e_shnum */
				m->n = k;
				m->rec_off = wide ? 64u : 52u;                                                                     /* the program headers */
				m->rec_size = wide ? 56u : 32u;
				m->rec_n = 2;
			} else {
				m->n = 0;
				m->rec_off = m->rec_size = m->rec_n = 0;
			}
			snprintf(name, sizeof name, "lg-t%u-%u", target, i);
			fz_corpus_add_map(c, name, G.b, G.n, m);
			made++;
		}
}

/*
 * THE GENERATED MODE. The input is [seed (8 bytes)][target][edits...]: the program is generated from the seed, compiled to the target and
 * built into an image that parses; each edit (3 bytes: 16 bits of offset into the CODE, a byte) then overwrites one byte of the code. The
 * driver's mutators change the seed, and so the whole program, and the edits, and so a handful of instructions: every iteration reaches the
 * routes with an image the parsers accept, where the mutated images above fail to parse nine times in ten.
 */
static void gen_seeds(struct fz_corpus *c)
{
	uint8_t b[16];
	unsigned i;

	for (i = 0; i < 16u; i++) {
		memset(b, 0, sizeof b);
		b[0] = (uint8_t)(i * 37u + 1u);
		b[8] = (uint8_t)(i % 4u);
		fz_corpus_add(c, "gen", b, sizeof b);
	}
}

static int gen_run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static struct diag_st st;
	struct lg_rng r;
	unsigned target, k;
	size_t i;
	uint64_t seed = 0;

	if (n < 9)
		return 1;
	for (i = 0; i < 8; i++)
		seed |= (uint64_t)in[i] << (8u * i);
	target = in[8] % 4u;
	r.s = seed * 0x9e3779b97f4a7c15ull + 1u;
	lg_generate(&P, &r, LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_DEAD | LG_F_MEM);
	if (P.bad || !lg_codegen(&C, &P, &r, (int)target) || !lg_build(&G, &C, &r, (int)lg_rnd(&r, 2u)))
		return 2;
	for (k = 9; k + 3u <= n && k < 9u + 3u * 64u; k += 3u) {
		uint32_t at = ((uint32_t)in[k] | ((uint32_t)in[k + 1u] << 8)) % (C.a.n ? C.a.n : 1u);

		if (G.code_off + at < G.n)
			G.b[G.code_off + at] = in[k + 2u];
	}
	memset(&st, 0, sizeof st);
	if (target >= LG_T_PE64) {
		if (!kgenome_pe_image_parse(kof_buf_make(G.b, G.n), &st.pi, &st.obj))
			return 3;
		st.obj.file_header = &st.pi;
	} else {
		if (!kgenome_elf_image_parse(kof_buf_make(G.b, G.n), &st.ei, &st.obj))
			return 3;
		st.obj.file_header = &st.ei;
	}
	/* THROTTLED: the scan of a generated dynamic image costs about 3 ms under the sanitisers (the lineage stages over its imports), and the
	 * smoke run has a budget in seconds for every stage; the generation, the edits and the parse are cheap and run every time, the scan one
	 * time in three (a campaign asks for three times the iterations). */
	if (fz_below(c->rng, 3) == 0)
		diag_exercise_ex(c, &st.obj, G.b, G.n, 1);
	fz_digest(c, G.n);
	return 0;
}

FZ_ADAPTER(scan_lineage_gen, .name = "kgenome/diag_scan_lineage_gen", .covers = "", .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000,
	   .steps_base = 4000000u, .steps_per_byte = 256, .shape = FZ_REQ, .seeds = gen_seeds, .run = gen_run);

static void walk_lite(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	diag_exercise_ex(c, &((struct diag_st *)h)->obj, in, n, 1);
}

FZ_ADAPTER(scan_lineage, .name = "kgenome/diag_scan_lineage", .covers = "", .flags = FZ_MAY_HIT_CAP, .backstop_s = 3000,
	   .steps_base = 4000000u, .steps_per_byte = 256, .shape = FZ_PARSE, .seeds = seeds, .dict = diag_dict_bin,
	   .parse = diag_parse_bin, .walk = walk_lite);
