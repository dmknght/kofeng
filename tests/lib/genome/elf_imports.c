/*
 * elf_imports - kgenome_elf_imports (genotype/image/elf_image.h), UNTESTED before this file (Phase 2 sweep,
 * owner's "cac ham, thuat toan nao chua co test case thi bo sung luon"): grep of tests/lib/genome and
 * tests/unit for the symbol found zero hits. diag_imports_status.c and imports_fuzz.c test the PE-side
 * import table (kgenome_pe_imptab / kgenome_diag_imports); this is the ELF one, which reads a linked
 * object's GOT-filling dynamic relocations (GLOB_DAT/JUMP_SLOT) against .dynsym - nothing else in the tree
 * exercises it.
 *
 * The writer below is self-contained (not fntab_kit.h/hk.h): a minimal ELF64 LE x86-64 ET_DYN with
 * .text .dynsym .dynstr .rela.dyn .shstrtab, offsets published in struct eimp so a hostile test corrupts
 * one field by name and nothing else.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/elf_types.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void w16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t *p, uint32_t v) { unsigned i; for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8u * i)); }
static void w64(uint8_t *p, uint64_t v) { unsigned i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8u * i)); }

#define EIMP_MAX 1024u

/* .text(16) .dynsym(3 Elf64_Sym: null, puts, exit) .dynstr("\0puts\0exit") .rela.dyn(2 Elf64_Rela:
 * GLOB_DAT puts@0x500000, JUMP_SLOT exit@0x500008) .shstrtab; 6 section headers. */
struct eimp {
	uint8_t b[EIMP_MAX];
	uint32_t n;
	uint32_t text, dynsym, dynstr, rela, shstr, sh;
};

static void eimp_build(struct eimp *e)
{
	static const char dynstr[] = "\0puts\0exit";
	static const char shstr[] = "\0.text\0.dynsym\0.dynstr\0.rela.dyn\0.shstrtab";
	uint8_t *b;
	uint32_t at;
	struct { uint32_t name, type; uint64_t flags; uint32_t off, size, link, info, ent; } s[6];
	uint32_t i;

	memset(e, 0, sizeof *e);
	b = e->b;
	e->text = 0x78u;                     /* ehdr 0x40 + phdr 0x38 (56), 8-aligned already */
	at = e->text + 16u;
	e->dynsym = (at + 7u) & ~7u;
	at = e->dynsym + 3u * 24u;            /* 3 Elf64_Sym */
	e->dynstr = at;
	at += (uint32_t)sizeof dynstr;
	e->rela = (at + 7u) & ~7u;
	at = e->rela + 2u * 24u;              /* 2 Elf64_Rela */
	e->shstr = at;
	at += (uint32_t)sizeof shstr;
	e->sh = (at + 7u) & ~7u;
	e->n = e->sh + 6u * 64u;

	b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F'; b[4] = 2; b[5] = 1; b[6] = 1;
	w16(b + 16, 3);                       /* e_type ET_DYN */
	w16(b + 18, 62);                      /* e_machine EM_X86_64 */
	w32(b + 20, 1);                       /* e_version */
	w64(b + 24, 0x400000u + e->text);     /* e_entry */
	w64(b + 32, 0x40u);                   /* e_phoff */
	w64(b + 40, e->sh);                   /* e_shoff */
	w16(b + 52, 64); w16(b + 54, 56); w16(b + 56, 1);        /* ehsize, phentsize, phnum */
	w16(b + 58, 64); w16(b + 60, 6); w16(b + 62, 5);         /* shentsize, shnum, shstrndx */

	{
		uint8_t *p = b + 0x40;         /* one PT_LOAD over the whole file, R+X */

		w32(p, 1); w32(p + 4, 5); w64(p + 8, 0); w64(p + 16, 0x400000u); w64(p + 24, 0x400000u);
		w64(p + 32, e->n); w64(p + 40, e->n); w64(p + 48, 0x1000);
	}
	memset(b + e->text, 0x90, 16);

	{
		uint8_t *sy = b + e->dynsym + 24u;             /* index 1: puts, undefined */

		w32(sy, 1); sy[4] = 0x12; sy[5] = 0; w16(sy + 6, 0); w64(sy + 8, 0); w64(sy + 16, 0);
		sy = b + e->dynsym + 48u;                      /* index 2: exit, undefined */
		w32(sy, 6); sy[4] = 0x12; sy[5] = 0; w16(sy + 6, 0); w64(sy + 8, 0); w64(sy + 16, 0);
	}
	memcpy(b + e->dynstr, dynstr, sizeof dynstr);

	{
		uint8_t *r = b + e->rela;

		w64(r, 0x500000u); w64(r + 8, ((uint64_t)1 << 32) | 6u); w64(r + 16, 0);       /* sym 1 (puts), GLOB_DAT */
		r = b + e->rela + 24u;
		w64(r, 0x500008u); w64(r + 8, ((uint64_t)2 << 32) | 7u); w64(r + 16, 0);       /* sym 2 (exit), JUMP_SLOT */
	}
	memcpy(b + e->shstr, shstr, sizeof shstr);

	memset(s, 0, sizeof s);
	s[1].name = 1;  s[1].type = 1;  s[1].flags = 6;    s[1].off = e->text;   s[1].size = 16;
	s[2].name = 7;  s[2].type = 11; s[2].flags = 2;    s[2].off = e->dynsym; s[2].size = 3u * 24u; s[2].link = 3; s[2].info = 1; s[2].ent = 24;
	s[3].name = 15; s[3].type = 3;  s[3].flags = 2;    s[3].off = e->dynstr; s[3].size = (uint32_t)sizeof dynstr;
	s[4].name = 23; s[4].type = 4;  s[4].flags = 0x42; s[4].off = e->rela;   s[4].size = 2u * 24u; s[4].link = 2; s[4].ent = 24;
	s[5].name = 33; s[5].type = 3;  s[5].flags = 0;    s[5].off = e->shstr;  s[5].size = (uint32_t)sizeof shstr;
	for (i = 0; i < 6; i++) {
		uint8_t *h = b + e->sh + i * 64u;

		w32(h, s[i].name); w32(h + 4, s[i].type); w64(h + 8, s[i].flags);
		w64(h + 16, 0); w64(h + 24, s[i].off); w64(h + 32, s[i].size);
		w32(h + 40, s[i].link); w32(h + 44, s[i].info); w64(h + 48, 8); w64(h + 56, s[i].ent);
	}
}

static int eparse(const uint8_t *b, uint32_t n, struct kgenome_elf_info *ei, struct kgenome_obj *o)
{
	memset(ei, 0, sizeof *ei);
	memset(o, 0, sizeof *o);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), ei, o))
		return 0;
	o->file_header = ei;
	return 1;
}

struct hit { uint64_t slot, nameoff; uint32_t type; char name[32]; };
static struct hit hits[8];
static unsigned n_hits;

static void on_import(void *user, uint64_t slot, uint64_t nameoff, uint32_t type, const char *name)
{
	(void)user;
	if (n_hits < 8) {
		hits[n_hits].slot = slot; hits[n_hits].nameoff = nameoff; hits[n_hits].type = type;
		snprintf(hits[n_hits].name, sizeof hits[n_hits].name, "%s", name ? name : "");
	}
	n_hits++;
}

static uint32_t run(const struct eimp *e, enum kgenome_status *st)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	uint32_t r;

	n_hits = 0;
	CK(eparse(e->b, e->n, &ei, &o));
	r = kgenome_elf_imports(kof_buf_make(e->b, e->n), &ei, on_import, NULL, st);
	CK(r == n_hits || n_hits > 8);
	return r;
}

int main(void)
{
	struct eimp e;

	/* the control: both GOT slots reported, exactly, in table order */
	eimp_build(&e);
	{
		enum kgenome_status st = KGENOME_BAD_INPUT;
		uint32_t r = run(&e, &st);

		CK(r == 2 && st == KGENOME_OK);
		CK(hits[0].slot == 0x500000u && hits[0].type == 6u && !strcmp(hits[0].name, "puts"));
		CK(hits[1].slot == 0x500008u && hits[1].type == 7u && !strcmp(hits[1].name, "exit"));
	}

	/* NULL safety: no crash, 0 reported */
	{
		struct kgenome_elf_info ei;
		struct kgenome_obj o;

		eimp_build(&e);
		CK(eparse(e.b, e.n, &ei, &o));
		CK(kgenome_elf_imports(kof_buf_make((const uint8_t *)NULL, 0), &ei, on_import, NULL, NULL) == 0);
		CK(kgenome_elf_imports(kof_buf_make(e.b, e.n), NULL, on_import, NULL, NULL) == 0);
		CK(kgenome_elf_imports(kof_buf_make(e.b, e.n), &ei, NULL, NULL, NULL) == 0);
	}

	/* ET_REL: an unlinked object has no GOT slots to fill - refused before any table is read */
	eimp_build(&e);
	w16(e.b + 16, 1);
	CK(run(&e, NULL) == 0);

	/* a machine this strategy does not cover (ARM): refused, valid dynamic tables notwithstanding */
	eimp_build(&e);
	w16(e.b + 18, 40);
	CK(run(&e, NULL) == 0);

	/* a relocation type that is neither GLOB_DAT nor JUMP_SLOT: that record is skipped, the other kept */
	eimp_build(&e);
	e.b[e.rela + 8] = 9;                 /* R_X86_64_GOT64 is not an import fill */
	CK(run(&e, NULL) == 1 && hits[0].type == 7u);

	/* a record naming symbol 0 (STN_UNDEF, "no symbol"): skipped */
	eimp_build(&e);
	w64(e.b + e.rela + 8, 6u);            /* sym 0, type GLOB_DAT */
	CK(run(&e, NULL) == 1 && hits[0].type == 7u);

	/* a record naming a symbol index past the table: skipped, not read out of bounds */
	eimp_build(&e);
	w64(e.b + e.rela + 8, ((uint64_t)99 << 32) | 6u);
	CK(run(&e, NULL) == 1 && hits[0].type == 7u);

	/* the symbol's own nameoff past .dynstr: skipped (a name that cannot be read is not reported) */
	eimp_build(&e);
	w32(e.b + e.dynsym + 24u, 9999u);     /* puts' nameoff, now past .dynstr's 10 bytes */
	CK(run(&e, NULL) == 1 && hits[0].type == 7u);

	/* .rela.dyn's sh_link does not name a DYNSYM section: the whole section is unreadable as imports */
	eimp_build(&e);
	w32(e.b + e.sh + 4u * 64u + 40u, 1u);  /* link -> .text (index 1), not .dynsym */
	CK(run(&e, NULL) == 0);

	/* no .dynsym at all (the section retyped as PROGBITS): nothing to name any relocation by */
	eimp_build(&e);
	w32(e.b + e.sh + 2u * 64u + 4u, 1u);   /* .dynsym's sh_type -> SHT_PROGBITS */
	CK(run(&e, NULL) == 0);

	/* .dynsym's sh_link names a section that is NOT a string table (.dynstr itself retyped to
	 * PROGBITS, .dynsym's sh_link still pointing at it): sec_strtab_of refuses it, t.strn stays 0,
	 * and kgenome_elf_imports' `!t.strn` guard refuses the whole table - distinct from the existing
	 * ".rela.dyn's sh_link wrong" and "no .dynsym at all" cases above: here BOTH .dynsym and
	 * .rela.dyn are intact and correctly linked, only the STRING section they agree on is not one. */
	eimp_build(&e);
	w32(e.b + e.sh + 3u * 64u + 4u, 1u);   /* .dynstr (section index 3)'s sh_type -> SHT_PROGBITS */
	CK(run(&e, NULL) == 0);

	/* .dynsym and .dynstr sections declared OVERLAPPING (dynstr's offset moved to land inside
	 * dynsym's own byte range): the format is self-contradictory but every read stays inside the
	 * file buffer (bounds come from the file's own length, not from neighbouring sections), so
	 * this is "no crash, a readable-but-wrong answer" and not a new hostile acceptance. */
	eimp_build(&e);
	w64(e.b + e.sh + 3u * 64u + 24u, (uint64_t)(e.dynsym + 8u));   /* .dynstr's file_off -> inside .dynsym */
	CK(run(&e, NULL) <= 2);

	/* the two relocation records swapped (non-increasing r_offset order): the reader walks the
	 * table in its own record order and never sorts or assumes sorted input by r_offset (checked
	 * in kgenome_elf_imports, libgenome/genotype/image/elf_image.c: the loop steps `k += step`
	 * through file position, and r.roff is read per record and handed straight to the callback),
	 * so reversing the two entries only reverses report order and changes nothing else. */
	eimp_build(&e);
	{
		uint8_t tmp[24];

		memcpy(tmp, e.b + e.rela, 24);
		memcpy(e.b + e.rela, e.b + e.rela + 24, 24);
		memcpy(e.b + e.rela + 24, tmp, 24);
	}
	CK(run(&e, NULL) == 2 && hits[0].slot == 0x500008u && hits[0].type == 7u &&
	   hits[1].slot == 0x500000u && hits[1].type == 6u);

	/* every single-byte flip of the two relocation records: no crash, never more than 2 reported */
	{
		unsigned i;

		for (i = 0; i < 48u; i++) {
			uint8_t keep;

			eimp_build(&e);
			keep = e.b[e.rela + i];
			e.b[e.rela + i] ^= 0xffu;
			CK(run(&e, NULL) <= 2);
			e.b[e.rela + i] = keep;
		}
	}

	/* every prefix of the file: no crash, no more than 2 reported */
	{
		uint32_t cut;

		eimp_build(&e);
		for (cut = 0; cut <= e.n; cut += 7u) {
			struct kgenome_elf_info ei;
			struct kgenome_obj o;

			n_hits = 0;
			if (eparse(e.b, cut, &ei, &o))
				CK(kgenome_elf_imports(kof_buf_make(e.b, cut), &ei, on_import, NULL, NULL) <= 2);
		}
	}

	printf("elf_imports: %d failure(s)\n", fails);
	return fails != 0;
}
