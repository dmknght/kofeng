/*
 * lineage_import - the nodes of a linked ELF and a PE: the calls that go through the PLT, the GOT or the import table,
 * found by name, and nothing else.
 *
 * WHAT IS HELD TO WHAT. A generated program (lineage_ir.h) is compiled to the four targets and scanned with the symbol
 * route alone: the nodes must be exactly the calls of the program to an import the vocabulary has a word for - the offset
 * of the call instruction, the capability and the name the node carries - once per call, with no link, and the two imports
 * with no capability must make none. The shapes of reaching an import the generator draws are the ones the route reads: a
 * lazy PLT stub, an IBT stub that begins with endbr64, the slot itself (-fno-plt), a thunk of a PE x86, ebx-relative slots in a
 * position-independent i386. Then the cases the generator does not make: a tail jump to a stub and to a slot is a node, the
 * stub's own `jmp [slot]` is not, and an ELF with no dynamic symbol table has no node.
 */
#include "lineage_check.h"

static void t_generated(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	int target, i, n = (int)(150 * hk_scale());
	long nodes = 0;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++)
		for (i = 0; i < n; i++) {
			struct lg_rng r;
			struct lg_scan sc;
			struct kgenome_diag_inputs in;
			uint32_t k, cnt;
			int s;

			r.s = ((uint64_t)i * 7919u + (uint64_t)target * 104729u + 77u) * 0x9e3779b97f4a7c15ull + 1u;
			lg_generate(&p, &r, LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_DEAD | LG_F_MEM);
			if (p.bad || !lg_codegen(&c, &p, &r, target) || !lg_build(&g, &c, &r, (int)lg_rnd(&r, 2u)))
				continue;
			memset(&sc, 0, sizeof sc);
			if (target >= LG_T_PE64) {
				CK(kgenome_pe_image_parse(kof_buf_make(g.b, g.n), &sc.pi, &sc.obj));
				sc.obj.file_header = &sc.pi;
			} else {
				CK(kgenome_elf_image_parse(kof_buf_make(g.b, g.n), &sc.ei, &sc.obj));
				sc.obj.file_header = &sc.ei;
			}
			memset(&in, 0, sizeof in);
			sc.s = kgenome_diag_scan_with_inputs(&sc.obj, g.b, g.n, KGENOME_DIAG_RUN_SYMBOL, &in);
			CK(sc.s != NULL);
			if (!sc.s)
				continue;
			cnt = kgenome_diag_scan_count(sc.s);
			CK(cnt == (uint32_t)p.nsite);
			for (s = 0; s < p.nsite; s++) {
				int found = 0;

				for (k = 0; k < cnt; k++) {
					const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc.s, k);

					if (h->at != g.code_off + c.site_off[s])
						continue;
					found++;
					CK(h->cap == lg_cap_of_site(&p, target, s));
					CK(h->n_in == 0);
					CK((h->bits & KGENOME_DIAG_H_SYMREF) && h->symref < g.n &&
					   !strcmp((const char *)g.b + h->symref, lg_import_name(target, p.site_api[s])));
				}
				CK(found == 1);
			}
			nodes += cnt;
			kgenome_diag_scan_free(sc.s);
		}
	printf("lineage_import: %ld nodes of generated programs checked\n", nodes);
}

/* The programs the generator does not make: a tail jump to a stub and one through a slot, written here. */
static void t_tails(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	int target;

	for (target = LG_T_ELF64; target <= LG_T_ELF32; target++) {
		struct lg_rng r = { 0x1234567u + (uint64_t)target };
		struct lg_scan sc;
		uint32_t at_stub, at_slot, i, cnt;

		memset(&p, 0, sizeof p);
		p.nf = 1;
		p.fn[0].body = lg_newblk(&p);
		p.fn[0].dead = -1;
		CK(lg_codegen(&c, &p, &r, target));
		la_align(&c.a, 16);
		at_stub = c.a.n;
		la_jmp_sym(&c.a, LG_SYM_STUB(1));       /* a tail jump to the stub of socket */
		la_align(&c.a, 16);
		at_slot = c.a.n;
		la_jmp_slot(&c.a, LG_SYM_SLOT(2));      /* and one through the slot of accept itself */
		CK(la_resolve_labels(&c.a));
		CK(lg_build(&g, &c, &r, 0));
		CK(lg_scan(&sc, &g, target, 0));
		cnt = kgenome_diag_scan_count(sc.s);
		/* the nodes are the two jumps; the stubs' own `jmp [slot]` are not nodes */
		CK(cnt == 2u);
		for (i = 0; i < cnt; i++) {
			const struct kgenome_diag_hit *h = kgenome_diag_scan_at(sc.s, i);

			CK(h->at == g.code_off + at_stub || h->at == g.code_off + at_slot);
		}
		kgenome_diag_scan_free(sc.s);
	}
}

/* An ELF with no dynamic symbol table - a static binary - has no imports and so no node of this route. */
static void t_static(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	struct lg_rng r = { 99u };
	struct lg_scan sc;
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	uint32_t i;

	memset(&p, 0, sizeof p);
	p.nf = 1;
	p.fn[0].body = lg_newblk(&p);
	p.fn[0].dead = -1;
	CK(lg_codegen(&c, &p, &r, LG_T_ELF64));
	CK(lg_build(&g, &c, &r, 0));
	/* remove the dynamic symbol table's type: the section is then not a symbol table */
	CK(kgenome_elf_image_parse(kof_buf_make(g.b, g.n), &ei, &o));
	for (i = 0; i < ei.sec_count; i++)
		if (ei.sec[i].type == 11u)
			lg_p32(g.b, (uint32_t)ei.shoff + i * 64u + 4u, 1u);     /* sh_type := PROGBITS */
	CK(lg_scan(&sc, &g, LG_T_ELF64, 0));
	CK(kgenome_diag_scan_count(sc.s) == 0u);
	kgenome_diag_scan_free(sc.s);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_generated();
	t_tails();
	t_static();
	printf("lineage_import: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
