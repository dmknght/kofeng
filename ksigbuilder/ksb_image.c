/*
 * ksb_image.c - What a linked module has to be, asked of the engine's own ELF
 *    and PE parsers.
 */

#include "ksb.h"

#include <analyzers/parsers/binaries/elf/elf_parse.h>

/*
 * ---------------------------------------------------------------------------
 * WHAT THE LINKED IMAGE HAS TO BE, ASKED OF THE ENGINE'S OWN PARSER.
 *
 * These questions - are there relocations, are there undefined symbols, is
 * there anything but the blob section, which entry point does it export and at
 * what offset - were asked by running readelf, nm and size and reading their
 * text. Four processes per module, a text format each, and a grep or an awk to
 * pull the answer out.
 *
 * They are all facts about an ELF file, and this program already links the
 * parser the SCANNER uses to read one. Asking that parser instead is shorter,
 * needs no toolchain beyond the compiler and linker, and - the part that
 * matters - checks the image with the same code that will later refuse it at
 * load time, rather than with a different program that might disagree.
 *
 * The symbol table is walked here rather than through kofsym.h: that layout is
 * built by the scanner for rules to match on, and what is wanted here is the
 * raw st_shndx and st_value of three specific names.
 * ---------------------------------------------------------------------------
 */

static uint64_t rd_le(const uint8_t *p, unsigned n)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		v |= (uint64_t)p[i] << (8u * i);
	return v;
}

/*
 * THE SAME FACTS OUT OF A COFF OBJECT, for the Windows half of the build.
 *
 * Windows asks two different files two different questions: the linked PE for
 * relocations and sections, and the OBJECT for symbols - because lld strips the
 * image's symbol table by default, so by the time the image exists there is
 * nothing left to ask which entry point it carries.
 *
 * A COFF symbol record is eighteen bytes and the format has not moved since
 * 1993: an eight byte name field that either holds the name or, when its first
 * four bytes are zero, an offset into the string table that follows the symbol
 * table. Reading it directly is shorter than the awk that read llvm-nm's output
 * and does not depend on that program being installed.
 */
int ksb_coff_read(const char *path, struct img_facts *out)
{
	uint8_t *b;
	size_t len;
	uint32_t symptr, nsym, strtab, i;

	memset(out, 0, sizeof *out);
	b = (uint8_t *)ksb_slurp(path, &len);
	if (!b)
		return 0;
	if (len < 20u) {
		free(b);
		return 0;
	}
	symptr = (uint32_t)rd_le(b + 8, 4);
	nsym = (uint32_t)rd_le(b + 12, 4);
	strtab = symptr + nsym * 18u;
	if (!symptr || !nsym || strtab > len) {
		free(b);
		return 0;
	}

	/*
	 * The sections, for the same question the ELF side asks of .data and
	 * .bss: does this module carry state.
	 *
	 * COFF has no single writable/non-writable pair that reads off a size
	 * report - .rdata is legitimately data and must not count - so the
	 * name is what decides, and -fdata-sections spells a global in
	 * .data$<name> or .bss$<name> rather than in a section called exactly
	 * .data. The prefix is therefore what is matched, not the whole name.
	 *
	 * A section header is forty bytes, after the twenty byte file header
	 * and whatever optional header it declares - an object declares none,
	 * but the field is read rather than assumed.
	 */
	{
		uint32_t nsec = (uint32_t)rd_le(b + 2, 2);
		uint32_t optsz = (uint32_t)rd_le(b + 16, 2);
		uint64_t at = 20u + optsz;

		for (i = 0; i < nsec; i++, at += 40u) {
			const uint8_t *s = b + at;
			char nm[9];
			uint64_t raw;

			if (at + 40u > (uint64_t)len)
				break;
			memcpy(nm, s, 8);
			nm[8] = 0;
			raw = rd_le(s + 16, 4);          /* SizeOfRawData */
			if (!strncmp(nm, ".bss", 4))
				out->bss_bytes += raw;
			else if (!strncmp(nm, ".data", 5))
				out->data_bytes += raw;
		}
	}

	for (i = 0; i < nsym; i++) {
		const uint8_t *e = b + symptr + (size_t)i * 18u;
		char name[64];
		int16_t sect;
		uint32_t value;

		if (symptr + (size_t)i * 18u + 18u > len)
			break;
		value = (uint32_t)rd_le(e + 8, 4);
		sect = (int16_t)rd_le(e + 12, 2);
		if (rd_le(e, 4) == 0) {
			uint32_t off = (uint32_t)rd_le(e + 4, 4);

			if (strtab + off >= len)
				goto next;
			snprintf(name, sizeof name, "%s",
				 (const char *)b + strtab + off);
		} else {
			size_t k;

			for (k = 0; k < 8u && e[k]; k++)
				name[k] = (char)e[k];
			name[k] = 0;
		}
		if (!name[0])
			goto next;
		/* Section 0 with a value of zero is an external nobody
		 * defined; with a non-zero value it is a common symbol, which
		 * is storage and therefore also refused. */
		if (sect == 0) {
			if (!out->undef[0] &&
			    (!strcmp(name, "kof_scan") ||
			     !strcmp(name, "kof_unpack")) == 0)
				snprintf(out->undef, sizeof out->undef, "%s",
					 name);
			goto next;
		}
		if (!strcmp(name, "kof_cure") || !strcmp(name, "kof_heur"))
			snprintf(out->retired, sizeof out->retired, "%.31s", name);
		if (!strcmp(name, "kof_scan") || !strcmp(name, "kof_unpack")) {
			out->n_entry++;
			/* Bounded explicitly: the three names it can be are
			 * all shorter than the field, and saying so is what
			 * stops the compiler warning about a truncation that
			 * cannot happen. */
			snprintf(out->entry_name, sizeof out->entry_name,
				 "%.31s", name);
			out->entry_off = value;
		}
next:
		/* Auxiliary records follow and are not symbols. */
		i += e[17];
	}
	free(b);
	return 1;
}

#ifdef _WIN32
/*
 * THE LINKED PE, asked the two questions the object cannot answer.
 *
 * Read with the engine's own PE collector rather than a second parser written
 * here, for the reason the ELF side reads its image with kof_elf_parse: a
 * disagreement between how the build reads a header and how the scanner reads
 * one is a disagreement nobody would find, and there is no reason to have two
 * of them.
 *
 * Symbols are NOT read here. lld strips the image's symbol table by default,
 * so which entry point a module exports and whether anything is undefined are
 * questions only the object can still answer - see ksb_coff_read.
 */
int ksb_pe_image_read(const char *path, struct img_facts *out)
{
	struct kgenome_pe_info *info;
	struct kof_obj_ctx ctx;
	uint8_t *buf;
	size_t len;
	kof_buf b;
	uint32_t i;
	int ok = 0;

	memset(out, 0, sizeof *out);
	buf = (uint8_t *)ksb_slurp(path, &len);
	if (!buf)
		return 0;
	info = calloc(1, sizeof *info);
	if (!info) {
		free(buf);
		return 0;
	}
	b.p = buf;
	b.n = len;
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(b, info, &ctx))
		goto done;

	/*
	 * A base relocation directory with anything in it means the image
	 * expects to be fixed up at whatever address it lands at, and the
	 * loader fixes up nothing: it copies the bytes and enters them.
	 */
	if (info->dir[KGENOME_PE_DIR_BASERELOC].size)
		out->have_reloc = 1;

	for (i = 0; i < info->sec_count; i++) {
		const struct kgenome_pe_sec *s = &info->sec[i];

		/* Everything was merged into .text at link time; anything else
		 * carrying content means the merge and the compiler's flags
		 * have drifted apart. */
		if (strcmp(s->name, ".text") != 0) {
			if (!out->extra_sec[0])
				snprintf(out->extra_sec, sizeof out->extra_sec,
					 "%s", s->name);
			continue;
		}
		out->blob_off = s->file_off;
		out->blob_len = s->file_size;
	}
	ok = out->blob_len != 0;
done:
	free(info);
	free(buf);
	return ok;
}
#endif /* _WIN32 */

/*
 * Every fact this build needs about one ELF, in one pass.
 *
 * `want_blob` names the section whose bytes become the module - ".blob" for the
 * linked image. When it is NULL only the object-level facts are filled, which
 * is what the pre-link check needs.
 */
int ksb_img_read(const char *path, const char *want_blob,
		 struct img_facts *out)
{
	static const char *const allowed[] = {
		".blob", ".symtab", ".strtab", ".shstrtab", NULL
	};
	struct kgenome_elf_info *info;
	/* Required, not optional: kof_elf_parse writes ctx->obj_size before it
	 * looks at anything, so a null one faults. Nothing here reads it back -
	 * this wants the sections, not an object identity. */
	struct kof_obj_ctx ctx;
	uint8_t *buf;
	size_t len;
	kof_buf b;
	uint32_t i;
	int is64, ok = 0;

	memset(out, 0, sizeof *out);
	buf = (uint8_t *)ksb_slurp(path, &len);
	if (!buf)
		return 0;
	info = calloc(1, sizeof *info);
	if (!info) {
		free(buf);
		return 0;
	}
	b.p = buf;
	b.n = len;
	memset(&ctx, 0, sizeof ctx);
	if (!kof_elf_parse(b, info, &ctx))
		goto done;
	is64 = info->elf_class == KGENOME_ELFCLASS_64;

	for (i = 0; i < info->sec_count; i++) {
		const struct kgenome_elf_sec *s = &info->sec[i];
		int j, known = 0;

		/* SHT_RELA is 4, SHT_REL is 9 - a relocation section at all
		 * means the loader would have work to do, and it has none. */
		if (s->type == 4u || s->type == 9u) {
			out->have_reloc = 1;
			if (!out->extra_sec[0])
				snprintf(out->extra_sec, sizeof out->extra_sec,
					 "%s", s->name);
		}
		for (j = 0; allowed[j]; j++)
			if (!strcmp(s->name, allowed[j]))
				known = 1;
		if (!known && s->name[0] && !out->extra_sec[0] &&
		    s->type != 4u && s->type != 9u &&
		    strcmp(s->name, ".rela.blob") != 0)
			snprintf(out->extra_sec, sizeof out->extra_sec, "%s",
				 s->name);
		/* SHF_WRITE is 1. .bss is SHT_NOBITS (8) and owns no file
		 * bytes, so its size is the only place its cost shows. */
		if ((s->flags & 1u) && s->type == 8u)
			out->bss_bytes += s->file_size;
		else if ((s->flags & 1u))
			out->data_bytes += s->file_size;
		if (want_blob && !strcmp(s->name, want_blob)) {
			out->blob_off = s->file_off;
			out->blob_len = s->file_size;
		}
	}

	/* The symbol table, walked directly: three names and whether anything
	 * is undefined is all this needs, and both are one field each. */
	for (i = 0; i < info->sec_count; i++) {
		const struct kgenome_elf_sec *st = &info->sec[i];
		const struct kgenome_elf_sec *str = NULL;
		uint64_t at, esz = is64 ? 24u : 16u;
		uint32_t k;

		if (st->type != 2u)          /* SHT_SYMTAB */
			continue;
		for (k = 0; k < info->sec_count; k++)
			if (info->sec[k].type == 3u &&
			    !strcmp(info->sec[k].name, ".strtab"))
				str = &info->sec[k];
		if (!str)
			continue;
		for (at = st->file_off; at + esz <= st->file_off + st->file_size;
		     at += esz) {
			const uint8_t *e = buf + at;
			uint32_t nameoff = (uint32_t)rd_le(e, 4);
			uint16_t shndx;
			uint64_t value;
			const char *nm;

			if (at + esz > len)
				break;
			if (is64) {
				shndx = (uint16_t)rd_le(e + 6, 2);
				value = rd_le(e + 8, 8);
			} else {
				value = rd_le(e + 4, 4);
				shndx = (uint16_t)rd_le(e + 14, 2);
			}
			if (str->file_off + nameoff >= len)
				continue;
			nm = (const char *)buf + str->file_off + nameoff;
			if (!nm[0])
				continue;
			if (!shndx) {        /* SHN_UNDEF */
				if (!out->undef[0])
					snprintf(out->undef, sizeof out->undef,
						 "%s", nm);
				continue;
			}
			if (!strcmp(nm, "kof_cure") || !strcmp(nm, "kof_heur"))
				snprintf(out->retired, sizeof out->retired, "%.31s", nm);
			if (!strcmp(nm, "kof_scan") || !strcmp(nm, "kof_unpack")) {
				out->n_entry++;
				snprintf(out->entry_name, sizeof out->entry_name,
					 "%s", nm);
				out->entry_off = value;
			}
		}
	}
	ok = 1;
done:
	free(info);
	free(buf);
	return ok;
}
