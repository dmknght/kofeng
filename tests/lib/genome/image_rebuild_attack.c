/*
 * image_rebuild_attack - kgenome_pe_write_hdr, kgenome_pe_layout_of and the import table writer
 * (round 2, fix_engine2): the lines the baseline never ran were the header's directory handling (a
 * directory the module rebuilt, the parent's directories carried only where they still point at a
 * section, the three that are never carried), hollow and padding sections, and every refusal of the layout
 * reader. The header is written from a declaration and READ BACK by the parser, so the oracle is the
 * declaration the test wrote, not a second reading of the writer's own bytes.
 */

#define _GNU_SOURCE

#include <kgenome.h>

#include "hk.h"
#include "image_kit.h"

static void result(const char *id, const char *what, int before)
{
	printf("%s %s: %s\n", id, what, hk_fails == before ? "ok" : "FAILED");
}

static struct kgenome_pe_info tmpl, back;
static struct kgenome_obj bo;

static void template_pe(int plus)
{
	unsigned i;

	memset(&tmpl, 0, sizeof tmpl);
	tmpl.valid = 1;
	tmpl.pe32_plus = (uint8_t)plus;
	tmpl.machine = plus ? 0x8664u : 0x14cu;
	tmpl.image_base = plus ? 0x140000000ull : 0x400000ull;
	tmpl.subsystem = 3;
	tmpl.dll_characteristics = 0x8140u;
	for (i = 0; i < 16u; i++) {
		tmpl.dir[i].rva = 0x1000u + 0x100u * i;      /* every one points into the first section */
		tmpl.dir[i].size = 0x10u + i;
	}
}

static void decl(struct kgenome_sec_decl *d, const char *name, uint64_t rva, uint64_t vsize, uint32_t perm, uint32_t flags)
{
	memset(d, 0, sizeof *d);
	snprintf(d->name, sizeof d->name, "%s", name);
	d->rva = rva; d->vsize = vsize; d->perm = perm; d->flags = flags;
}

static int reparse(const uint8_t *img, uint64_t n)
{
	memset(&back, 0, sizeof back);
	memset(&bo, 0, sizeof bo);
	return kgenome_pe_image_parse(kof_buf_make(img, n), &back, &bo);
}

static void t_write_hdr(void)
{
	static uint8_t img[0x4000];
	struct kgenome_sec_decl s[5];
	struct kgenome_dir_decl dir[16];
	unsigned plus, i;
	int before = hk_fails;

	for (plus = 0; plus < 2u; plus++) {
		uint64_t need;

		template_pe((int)plus);
		decl(&s[0], ".text", 0x1000, 0x800, KGENOME_PE_PERM_R | KGENOME_PE_PERM_X, KGENOME_SECF_CODE);
		decl(&s[1], ".pad", 0x1800, 0x800, KGENOME_PE_PERM_R, KGENOME_SECF_PAD);
		decl(&s[2], ".data", 0x2000, 0x400, KGENOME_PE_PERM_R | KGENOME_PE_PERM_W, KGENOME_SECF_DATA);
		decl(&s[3], ".hollow", 0x2400, 0x400, KGENOME_PE_PERM_R | KGENOME_PE_PERM_W, KGENOME_SECF_DATA | KGENOME_SECF_HOLLOW);
		decl(&s[4], ".rwx", 0x3000, 0x200, KGENOME_PE_PERM_R | KGENOME_PE_PERM_X, KGENOME_SECF_DATA);
		memset(dir, 0, sizeof dir);
		dir[3].set = 1; dir[3].rva = 0x2100; dir[3].size = 0x44;        /* rebuilt by the module: wins */
		dir[1].set = 1; dir[1].rva = 0x3000; dir[1].size = 0x20;        /* even the import entry */
		memset(img, 0, sizeof img);
		need = kgenome_pe_write_hdr(img, 0x1000, &tmpl, s, 5, 0x1040, 0x3200, dir);
		CK(need == 0x80u + 24u + (plus ? 0xf0u : 0xe0u) + 4u * 40u);        /* four sections: the padding is not one */
		CK(reparse(img, 0x3200));
		CK(back.valid && back.pe32_plus == plus && back.machine == tmpl.machine);
		CK(back.image_base == tmpl.image_base && back.subsystem == 3 && back.dll_characteristics == 0x8140u);
		CK(back.nsec == 4u && back.sec_count == 4u);
		CK(back.entry_rva == 0x1040u && back.size_of_image == 0x3200u);
		CK(back.n_dirs == 16u);
		CK(!strcmp(back.sec[0].name, ".text") && back.sec[0].mem_rva == 0x1000 && back.sec[0].mem_size == 0x800);
		CK(!strcmp(back.sec[1].name, ".data") && back.sec[1].mem_rva == 0x2000);
		CK(!strcmp(back.sec[2].name, ".hollow") && back.sec[2].file_size == 0 && back.sec[2].file_off == 0);   /* declared, no bytes */
		CK(back.sec[1].file_size == 0x400 && back.sec[0].file_size == 0x800);
		CK(back.sec[0].perm == (KGENOME_PE_PERM_R | KGENOME_PE_PERM_X));
		CK((back.sec[0].characteristics & 0x00000020u) && (back.sec[0].characteristics & 0x20000000u));   /* CNT_CODE, MEM_EXECUTE */
		CK((back.sec[1].characteristics & 0x80000000u) && (back.sec[1].characteristics & 0x00000040u));   /* write, initialised data */
		CK((back.sec[2].characteristics & 0x00000080u));                                                  /* uninitialised data */
		CK((back.sec[3].characteristics & 0x20000000u));                                                  /* perm X without CODE: execute */
		/* the module's directories win; the parent's are carried where they still point into a section, and
		 * the import, security and relocation ones of the PARENT are dropped (the module's import wins) */
		CK(back.dir[3].rva == 0x2100 && back.dir[3].size == 0x44);
		CK(back.dir[1].rva == 0x3000 && back.dir[1].size == 0x20);
		CK(back.dir[0].rva == tmpl.dir[0].rva && back.dir[0].size == tmpl.dir[0].size);
		CK(back.dir[9].rva == tmpl.dir[9].rva && back.dir[9].size == tmpl.dir[9].size);
		CK(back.dir[KGENOME_PE_DIR_SECURITY].rva == 0 && back.dir[KGENOME_PE_DIR_BASERELOC].rva == 0);
		/* a parent directory that points at no declared section is not carried; zero rva or size neither */
		template_pe((int)plus);
		tmpl.dir[6].rva = 0x9000;                    /* nowhere */
		tmpl.dir[7].rva = 0x1000; tmpl.dir[7].size = 0;
		tmpl.dir[8].rva = 0; tmpl.dir[8].size = 8;
		memset(img, 0, sizeof img);
		(void)kgenome_pe_write_hdr(img, 0x1000, &tmpl, s, 5, 0x1040, 0x3200, NULL);
		CK(reparse(img, 0x3200));
		CK(back.dir[6].rva == 0 && back.dir[7].rva == 0 && back.dir[8].rva == 0);
		CK(back.dir[1].rva == 0);                    /* the import is the parent's and dropped with no module's */
		/* refusals: no room in front of the content, no section, only padding, no template, no buffer */
		CK(kgenome_pe_write_hdr(img, 0x100, &tmpl, s, 5, 0x1040, 0x3200, NULL) == 0);
		CK(kgenome_pe_write_hdr(img, 0x1000, &tmpl, s, 0, 0x1040, 0x3200, NULL) == 0);
		CK(kgenome_pe_write_hdr(img, 0x1000, &tmpl, &s[1], 1, 0x1040, 0x3200, NULL) == 0);
		CK(kgenome_pe_write_hdr(img, 0x1000, NULL, s, 5, 0x1040, 0x3200, NULL) == 0);
		CK(kgenome_pe_write_hdr(NULL, 0x1000, &tmpl, s, 5, 0x1040, 0x3200, NULL) == 0);
		CK(kgenome_pe_write_hdr(img, 0x1000, &tmpl, NULL, 5, 0x1040, 0x3200, NULL) == 0);
		(void)i;
	}
	result("R1 ", "pe header written from a declaration, read back", before);
}

static uint8_t img[0x2000];

/* a PE image whose header is somewhere inside the buffer (UPX leaves the program's own header in the payload) */
static void layout_image(struct ik_pe *p, uint32_t at)
{
	uint8_t tmp[0x1000];

	memset(img, 0xcc, sizeof img);
	memset(tmp, 0, sizeof tmp);
	(void)ik_pe_write(tmp, p);
	/* the DOS header and everything up to the end of the section table, moved to `at` */
	memcpy(img + at, tmp + 0x80, at + 0x400u <= sizeof img ? 0x400u : sizeof img - at);
}

static void t_layout(void)
{
	struct ik_pe p;
	struct kgenome_sec_decl out[8];
	struct kgenome_dir_decl dir[16];
	uint64_t entry = 0, base = 0;
	uint32_t n;
	unsigned plus, k;
	int before = hk_fails;

	for (plus = 0; plus < 2u; plus++) {
		memset(&p, 0, sizeof p);
		p.plus = (int)plus;
		p.entry = 0x1234;
		p.image_base = plus ? 0x140000000ull : 0x400000ull;
		p.size_of_image = 0x5000;
		p.size_of_headers = 0x200;
		/* declared out of order: a table is SORTED, never cut at the first entry out of place */
		ik_sec(&p, ".b", 0x300, 0x3000, 0x200, 0x600, IK_DATA);
		ik_sec(&p, ".a", 0x400, 0x1000, 0x200, 0x400, IK_TEXT);
		ik_sec(&p, ".zero", 0, 0x4000, 0, 0, IK_DATA);          /* an empty one is skipped */
		ik_sec(&p, ".norva", 0x100, 0, 0x100, 0x800, IK_DATA);   /* and one at rva 0 */
		ik_sec(&p, ".c", 0x100, 0x2000, 0x100, 0x800, IK_RDATA);
		p.dir_rva[KGENOME_PE_DIR_IMPORT] = 0x3010; p.dir_size[KGENOME_PE_DIR_IMPORT] = 0x40;
		p.dir_rva[KGENOME_PE_DIR_SECURITY] = 0x3020; p.dir_size[KGENOME_PE_DIR_SECURITY] = 0x40;
		p.dir_rva[KGENOME_PE_DIR_BASERELOC] = 0x3030; p.dir_size[KGENOME_PE_DIR_BASERELOC] = 0x40;
		p.dir_rva[2] = 0x2010; p.dir_size[2] = 0x10;
		p.dir_rva[6] = 0x3040; p.dir_size[6] = 0;                /* no size: not carried */
		layout_image(&p, 0x300);
		memset(out, 0, sizeof out);
		memset(dir, 0, sizeof dir);
		n = kgenome_pe_layout_of(kof_buf_make(img, sizeof img), out, 8, &entry, &base, dir);
		CK(n == 3u);
		CK(out[0].rva == 0x1000 && out[1].rva == 0x2000 && out[2].rva == 0x3000);
		CK(!strcmp(out[0].name, ".a") && !strcmp(out[2].name, ".b"));
		CK(out[0].vsize == 0x400 && (out[0].flags & KGENOME_SECF_CODE) && (out[0].flags & KGENOME_SECF_REBUILT));
		CK((out[1].flags & KGENOME_SECF_DATA) && !(out[1].flags & KGENOME_SECF_CODE));
		CK(out[0].perm == (KGENOME_PE_PERM_R | KGENOME_PE_PERM_X));
		CK(entry == 0x1234u && base == p.image_base);
		CK(dir[2].set && dir[2].rva == 0x2010 && dir[2].size == 0x10);
		CK(!dir[KGENOME_PE_DIR_SECURITY].set && !dir[KGENOME_PE_DIR_BASERELOC].set);     /* neither survives the move */
		CK(dir[KGENOME_PE_DIR_IMPORT].set && dir[KGENOME_PE_DIR_IMPORT].rva == 0x3010);
		CK(!dir[6].set);
		/* the room of the caller bounds what is declared */
		memset(out, 0, sizeof out);
		CK(kgenome_pe_layout_of(kof_buf_make(img, sizeof img), out, 2, NULL, NULL, NULL) == 2u);
		/* no cap, no output, no image */
		CK(kgenome_pe_layout_of(kof_buf_make(img, sizeof img), out, 0, NULL, NULL, NULL) == 0u);
		CK(kgenome_pe_layout_of(kof_buf_make(img, sizeof img), NULL, 8, NULL, NULL, NULL) == 0u);
		CK(kgenome_pe_layout_of(kof_buf_make(NULL, 0), out, 8, NULL, NULL, NULL) == 0u);
		/* a directory count that stops short of the table reads what it holds */
		ik_w32(img + 0x300 + 24 + (plus ? 108u : 92u) - 0x80 + 0x80, 3);
		(void)k;
	}
	/* every refusal of header_plausible: the header must be a PE header that could be true */
	{
		struct ik_pe q;
		uint32_t at = 0x300;
		struct { const char *what; uint32_t off; uint32_t val; unsigned w; } bad[] = {
			{ "no sections",        0x80 + 6,  0,      2 }, { "too many sections", 0x80 + 6, 97, 2 },
			{ "optional header too small", 0x80 + 20, 95, 2 }, { "optional header past the object", 0x80 + 20, 0x4000, 2 },
			{ "machine zero",       0x80 + 4,  0,      2 }, { "no optional magic", 0x98, 0x1234, 2 },
		};
		for (k = 0; k < sizeof bad / sizeof bad[0]; k++) {
			memset(&q, 0, sizeof q);
			q.entry = 0x1000;
			ik_sec(&q, ".a", 0x400, 0x1000, 0x200, 0x400, IK_TEXT);
			layout_image(&q, at);
			if (bad[k].w == 2)
				ik_w16(img + at + bad[k].off - 0x80, (uint16_t)bad[k].val);
			if (kgenome_pe_layout_of(kof_buf_make(img, sizeof img), out, 8, NULL, NULL, NULL) != 0u)
				printf("  refusal missing: %s\n", bad[k].what);
			CK(kgenome_pe_layout_of(kof_buf_make(img, sizeof img), out, 8, NULL, NULL, NULL) == 0u);
		}
		/* a section table that runs past the buffer */
		memset(&q, 0, sizeof q);
		ik_sec(&q, ".a", 0x400, 0x1000, 0x200, 0x400, IK_TEXT);
		layout_image(&q, 0x2000 - 4 - 20 - 224 - 20);          /* the table has 20 of its 40 bytes */
		CK(kgenome_pe_layout_of(kof_buf_make(img, sizeof img), out, 8, NULL, NULL, NULL) == 0u);
	}
	result("R2 ", "layout read out of an image", before);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_write_hdr();
	t_layout();
	if (hk_fails) {
		printf("image_rebuild_attack: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("image_rebuild_attack: ok\n");
	return 0;
}
