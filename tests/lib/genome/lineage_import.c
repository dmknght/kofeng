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
 * stub's own `jmp [slot]` is not, and an ELF with no dynamic symbol table has no node. And the node carries its import's ROW (t_row_carried).
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

/*
 * THE ROW A NODE CARRIES is the import's (kgenome_diag_hit.row, set by the route that read the name) and the lineage asks it whether
 * the result is an object (fix_linrow). `mprotect` is the one ELF row whose answer differs from its capability's: an executable
 * mapping's capability hands the region on (mmap), mprotect hands back a status. The fixture's import `getpid` is renamed in the
 * dynamic string table to `mprotect` (it fits over "getpid\0rand\0"; `rand`, which loses its name, has no word either way), and
 * write(<its result>) must not be linked to it. CONTROL: write(<socket's result>) is. Why missed: (b) no fixture imported a call whose
 * row and capability disagree, and the route's row was not carried (a mutant that drops it changed no test).
 */
static void t_row_carried(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	int control;

	for (control = 0; control < 2; control++) {
		struct lg_rng r = { 0x5151u };
		struct lg_scan sc;
		static struct lg_links got;
		uint32_t i, at;
		int renamed = 0;

		memset(&p, 0, sizeof p);
		p.nf = 1;
		p.fn[0].body = lg_newblk(&p);
		p.fn[0].dead = -1;
		CK(lg_codegen(&c, &p, &r, LG_T_ELF64));
		la_align(&c.a, 16);
		at = c.a.n;
		la_spadj(&c.a, 1, 0x18);
		la_movi(&c.a, LA_DI, 2);
		la_call_sym(&c.a, LG_SYM_STUB(control ? 1 : LG_IMP_COND));     /* socket, or getpid renamed mprotect */
		la_mov(&c.a, LA_DI, LA_AX);
		la_call_sym(&c.a, LG_SYM_STUB(8));                             /* write */
		la_spadj(&c.a, 0, 0x18);
		la_ret(&c.a);
		CK(la_resolve_labels(&c.a));
		/* the code above is the function the symbol table names (2026-11-16: the function table is made from metadata only; a stripped image with no
		 * unwind data is one unpartitioned unit, and this row is about the import's row, not about the partition) */
		c.fn_off[0] = at;
		c.fn_end[0] = c.a.n;
		CK(lg_build(&g, &c, &r, 1));
		for (i = 0; i + 12u <= g.n; i++)
			if (!memcmp(g.b + i, "getpid\0rand\0", 12)) {
				memcpy(g.b + i, "mprotect\0nd\0", 12);
				renamed = 1;
				break;
			}
		CK(renamed);
		CK(lg_scan(&sc, &g, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW));
		lg_actual(&got, &sc);
		if (control) {
			CK(got.n == 1u && got.v[0].role == KGENOME_DIAG_ROLE_FD);
		} else {
			CK(kgenome_diag_scan_count(sc.s) == 2u);        /* mprotect and write are nodes */
			if (got.n)
				printf("  row_carried: write's descriptor linked to mprotect's status\n");
			CK(got.n == 0u);
		}
		kgenome_diag_scan_free(sc.s);
	}
}

/*
 * AN i386 STDCALL IMPORT BY ORDINAL pops its arguments like one by name: the count is read from the name of the node's ROW (an ordinal
 * import has no name in the file, and the row the PE route carries gives it one: kgenome_nucleo_ordinal_name). WS2_32 #23 socket(2,1,6),
 * then #4 connect(<its result>, 0, 16) with the arguments pushed after the socket call returned: the descriptor is found only when the
 * stack pointer after socket is known, so the link says the pop count was read. CONTROL: the same imports by name. Why missed: (b) every
 * PE32 fixture imported by name, and the ordinal route (fix_roles) was tested on PE32+ only, where the callee pops nothing.
 */
static void t_ordinal_pe32(void)
{
	static struct lg_img g;
	static struct lg_cg c;
	static struct lg_prog p;
	int by_ordinal;

	for (by_ordinal = 0; by_ordinal < 2; by_ordinal++) {
		struct lg_rng r = { 0x2323u };
		struct lg_scan sc;
		static struct lg_links got;
		const uint32_t hdr = 0x400, idata = 0x4000;
		uint32_t at_code, k;

		memset(&p, 0, sizeof p);
		p.nf = 1;
		p.fn[0].body = lg_newblk(&p);
		p.fn[0].dead = -1;
		CK(lg_codegen(&c, &p, &r, LG_T_PE32));
		la_align(&c.a, 16);
		at_code = c.a.n;
		la_pushi(&c.a, 6);
		la_pushi(&c.a, 1);
		la_pushi(&c.a, 2);
		la_call_slot(&c.a, LG_SYM_SLOT(1));             /* socket: pops 12 */
		la_pushi(&c.a, 16);
		la_pushi(&c.a, 0);
		la_push(&c.a, LA_AX);
		la_call_slot(&c.a, LG_SYM_SLOT(4));             /* connect(s, 0, 16): pops 12 */
		la_ret(&c.a);
		CK(la_resolve_labels(&c.a));
		/* round 4: the entry point declares a start, not a body - the code above is the function the image's COFF symbol (lg_build_pe) sizes */
		c.fn_off[0] = at_code;
		c.fn_end[0] = c.a.n;
		CK(lg_build(&g, &c, &r, 0));
		lg_p32(g.b, 0x80u + 24u + 16u, 0x1000u + at_code);     /* the entry point: the code above */
		memcpy(g.b + hdr + idata + 0x2f0u, "WS2_32.dll", 11);
		if (by_ordinal)
			for (k = 0; k < 2u; k++) {
				const uint32_t imp = k ? 4u : 1u, ord = k ? 4u : 23u;

				lg_p32(g.b, hdr + idata + 0x100u + 4u * (imp - 1u), 0x80000000u | ord);  /* ILT */
				lg_p32(g.b, hdr + idata + 0x200u + 4u * (imp - 1u), 0x80000000u | ord);  /* IAT */
			}
		CK(lg_scan(&sc, &g, LG_T_PE32, KGENOME_LINEAGE_S_FLOW));
		CK(kgenome_diag_scan_count(sc.s) == 2u);
		lg_actual(&got, &sc);
		if (!(got.n == 1u && got.v[0].role == KGENOME_DIAG_ROLE_FD))
			printf("  ordinal_pe32 (%s): %d link(s), want connect's descriptor <- socket\n", by_ordinal ? "by ordinal" : "by name", got.n);
		CK(got.n == 1u && got.v[0].role == KGENOME_DIAG_ROLE_FD);
		kgenome_diag_scan_free(sc.s);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_generated();
	t_tails();
	t_static();
	t_row_carried();
	t_ordinal_pe32();
	printf("lineage_import: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
