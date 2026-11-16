/*
 * audit_pmeta_kit.h - the object builders of the audit_pmeta_* tests (independent audit of the metadata-only function
 * table, 2026-11-16). Header only, every helper static. Objects are BUILT IN MEMORY from the field values a test names,
 * with the offsets the test chooses, so the oracle (what readelf / the PE spec says the object declares) is written next
 * to the check. Nothing here reads the engine's partition code.
 *
 *   ak_elf   ELF32/ELF64, LE, ET_EXEC or ET_REL: sections at caller-given file offsets (address = base + offset when
 *            SHF_ALLOC and not ET_REL), one PT_LOAD R-X over the whole file for ET_EXEC, an optional section table.
 *   ak_sym   a .symtab entry (name, value = section offset or address, size, info, section index).
 *   ak_table the engine's function table of an image (kgenome_elf_image_parse / kgenome_pe_image_parse +
 *            kgenome_diag_funcs_of), the one table every consumer reads.
 */
#ifndef KGENOME_TESTS_AUDIT_PMETA_KIT_H
#define KGENOME_TESTS_AUDIT_PMETA_KIT_H

#include <kgenome.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_image.h>
#include <genotype/image/funcs.h>
#include <phenotype/diag_scan.h>

#include "hk.h"

#define AK_MAXSEC 12

static HK_UNUSED void ak16(uint8_t *p, uint64_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static HK_UNUSED void ak32(uint8_t *p, uint64_t v) { ak16(p, v); ak16(p + 2, v >> 16); }
static HK_UNUSED void ak64(uint8_t *p, uint64_t v) { ak32(p, v); ak32(p + 4, v >> 32); }

struct ak_sec {
	const char *name;
	uint32_t type;
	uint64_t flags;
	uint64_t off;           /* file offset the test chooses */
	uint64_t size;
	uint32_t link, info;
	uint64_t entsize;
};

struct ak_elf {
	int is64;
	uint16_t machine;
	uint16_t etype;         /* 1 ET_REL, 2 ET_EXEC */
	uint32_t eflags;
	uint64_t base;          /* address of file offset 0 (ET_EXEC) */
	uint64_t entry;
	int no_shdr;            /* 1: write no section table (sections still lay their bytes) */
	uint64_t size;          /* file size */
	struct ak_sec sec[AK_MAXSEC];   /* sec[0] is the null section */
	unsigned nsec;
};

static HK_UNUSED uint64_t ak_addr(const struct ak_elf *e, uint64_t off)
{
	return e->etype == 1 ? 0 : e->base + off;
}

/* Write the headers, the program header and the section table (with a .shstrtab at `shs_off`) into img. The caller has
 * already put the sections' bytes at their offsets; shdr at `sh_off`. Answers the file size. */
static HK_UNUSED size_t ak_elf_finish(uint8_t *img, size_t cap, struct ak_elf *e, uint64_t shs_off, uint64_t sh_off)
{
	unsigned i;
	uint64_t n = 1;
	unsigned shs_idx = e->nsec;
	size_t shent = e->is64 ? 64 : 40;
	size_t size;

	/* .shstrtab */
	img[shs_off] = 0;
	for (i = 1; i < e->nsec; i++) {
		size_t l = strlen(e->sec[i].name) + 1;
		memcpy(img + shs_off + n, e->sec[i].name, l);
		n += l;
	}
	memcpy(img + shs_off + n, ".shstrtab", 10);
	n += 10;
	size = (size_t)(sh_off + (e->no_shdr ? 0 : shent * (e->nsec + 1)));
	if (size > cap || shs_off + n > sh_off)
		return 0;
	if (e->size > size)
		size = (size_t)e->size;
	memcpy(img, "\x7f" "ELF", 4);
	img[4] = e->is64 ? 2 : 1;
	img[5] = 1;
	img[6] = 1;
	ak16(img + 16, e->etype);
	ak16(img + 18, e->machine);
	ak32(img + 20, 1);
	if (e->is64) {
		ak64(img + 24, e->entry);
		ak64(img + 32, e->etype == 1 ? 0 : 64);
		ak64(img + 40, e->no_shdr ? 0 : sh_off);
		ak32(img + 48, e->eflags);
		ak16(img + 52, 64); ak16(img + 54, 56); ak16(img + 56, e->etype == 1 ? 0 : 1);
		ak16(img + 58, 64); ak16(img + 60, e->no_shdr ? 0 : e->nsec + 1); ak16(img + 62, e->no_shdr ? 0 : shs_idx);
		if (e->etype != 1) {
			ak32(img + 64, 1); ak32(img + 68, 5); ak64(img + 72, 0); ak64(img + 80, e->base); ak64(img + 88, e->base);
			ak64(img + 96, size); ak64(img + 104, size); ak64(img + 112, 0x1000);
		}
	} else {
		ak32(img + 24, e->entry);
		ak32(img + 28, e->etype == 1 ? 0 : 52);
		ak32(img + 32, e->no_shdr ? 0 : sh_off);
		ak32(img + 36, e->eflags);
		ak16(img + 40, 52); ak16(img + 42, 32); ak16(img + 44, e->etype == 1 ? 0 : 1);
		ak16(img + 46, 40); ak16(img + 48, e->no_shdr ? 0 : e->nsec + 1); ak16(img + 50, e->no_shdr ? 0 : shs_idx);
		if (e->etype != 1) {
			ak32(img + 52, 1); ak32(img + 56, 0); ak32(img + 60, e->base); ak32(img + 64, e->base);
			ak32(img + 68, size); ak32(img + 72, size); ak32(img + 76, 5); ak32(img + 80, 0x1000);
		}
	}
	if (e->no_shdr)
		return size;
	n = 1;
	for (i = 1; i <= e->nsec; i++) {
		uint8_t *s = img + sh_off + shent * i;
		const struct ak_sec *c = i < e->nsec ? &e->sec[i] : NULL;
		uint64_t nm = n, type = c ? c->type : 3, flags = c ? c->flags : 0, off = c ? c->off : shs_off;
		uint64_t sz = c ? c->size : 0, addr = c && (flags & 2) ? ak_addr(e, off) : 0;

		if (c)
			n += strlen(c->name) + 1;
		else {
			uint64_t k = 1;
			for (unsigned j = 1; j < e->nsec; j++)
				k += strlen(e->sec[j].name) + 1;
			sz = k + 10;
		}
		if (e->is64) {
			ak32(s, nm); ak32(s + 4, type); ak64(s + 8, flags); ak64(s + 16, addr); ak64(s + 24, off); ak64(s + 32, sz);
			ak32(s + 40, c ? c->link : 0); ak32(s + 44, c ? c->info : 0); ak64(s + 48, 1); ak64(s + 56, c ? c->entsize : 0);
		} else {
			ak32(s, nm); ak32(s + 4, type); ak32(s + 8, flags); ak32(s + 12, addr); ak32(s + 16, off); ak32(s + 20, sz);
			ak32(s + 24, c ? c->link : 0); ak32(s + 28, c ? c->info : 0); ak32(s + 32, 1); ak32(s + 36, c ? c->entsize : 0);
		}
	}
	return size;
}

/* One .symtab entry at img + at (24 bytes for ELF64, 16 for ELF32). info = (bind << 4) | type. */
static HK_UNUSED void ak_sym(uint8_t *img, uint64_t at, int is64, uint32_t name, uint64_t value, uint64_t size, uint8_t info,
			     uint16_t shndx)
{
	if (is64) {
		ak32(img + at, name); img[at + 4] = info; img[at + 5] = 0; ak16(img + at + 6, shndx);
		ak64(img + at + 8, value); ak64(img + at + 16, size);
	} else {
		ak32(img + at, name); ak32(img + at + 4, value); ak32(img + at + 8, size); img[at + 12] = info; img[at + 13] = 0;
		ak16(img + at + 14, shndx);
	}
}

/* The engine's function table of img[0..n): 1 when the image parsed. */
static HK_UNUSED int ak_table(const uint8_t *img, size_t n, struct kgenome_func_set *fs)
{
	static struct kgenome_elf_info ei;
	static struct kgenome_pe_info pi;
	struct kgenome_obj obj;

	memset(&ei, 0, sizeof ei);
	memset(&pi, 0, sizeof pi);
	memset(&obj, 0, sizeof obj);
	memset(fs, 0, sizeof *fs);
	if (kgenome_elf_image_parse(kof_buf_make(img, n), &ei, &obj))
		obj.file_header = &ei;
	else if (kgenome_pe_image_parse(kof_buf_make(img, n), &pi, &obj))
		obj.file_header = &pi;
	else
		return 0;
	kgenome_diag_funcs_of(&obj, img, n, fs);
	return 1;
}

/* Bytes of [lo, hi) that no entry of the table holds (every range of every entry counted). */

/* Round 4 (2026-11-16, the coordinator's revised model): a start-only source declares a START, held by the table's sorted starts; the source bits of the
 * declared start at `off`, or 0 (added by the implementer when the rule changed; the audit's own checks are unchanged otherwise). */
static HK_UNUSED unsigned ak_start_src(const struct kgenome_func_set *fs, uint64_t off, unsigned *isa)
{
	uint32_t i;

	for (i = 0; i < fs->n_st; i++)
		if (fs->st[i].off == off) {
			if (isa)
				*isa = fs->st[i].isa_mode;
			return fs->st[i].source;
		}
	return 0;
}

static HK_UNUSED uint64_t ak_uncovered(const struct kgenome_func_set *fs, uint64_t lo, uint64_t hi)
{
	uint64_t miss = 0;

	for (uint64_t o = lo; o < hi; o++) {
		int in = 0;
		for (uint32_t i = 0; i < fs->n && !in; i++)
			for (uint32_t k = 0; k < kgenome_funcs_n_ranges(fs, i) && !in; k++) {
				struct kgenome_func_range r = kgenome_funcs_range(fs, i, k);
				in = o >= r.off && o < r.off + r.len;
			}
		miss += !in;
	}
	return miss;
}

#endif
