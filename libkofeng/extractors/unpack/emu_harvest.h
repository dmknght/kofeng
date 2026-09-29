/*
 * emu_harvest.h - what a module does with the regions an interpreter run left.
 *
 * SHARED BECAUSE THE ANSWER IS THE SAME, NOT BECAUSE THE QUESTION IS.
 *
 * Two modules drive the interpreter for different reasons. `pecompact_pe.c`
 * recognised its packer and knows statically that it cannot decode the codec,
 * so it VOUCHES for a run and names the level that vouch is worth paying at.
 * `emu_generic_00.c` recognised nothing and asks unvouched, letting the host's
 * own density gate decide. What they do with what comes back is one procedure,
 * and a second copy of it is the thing the object pipeline forbids: no module
 * may carry its own way of creating objects or declaring regions.
 *
 * A header and not engine code, and that distinction is the whole architecture.
 * Deciding that a written page IS an image, or that four heap pages and an
 * image are ONE program, is a judgement about meaning - which is exactly the
 * decision the interpreter is not allowed to make, because it is the component
 * that executes hostile bytes. So the judgement lives on the module side.
 *
 * IT SITS IN kofmod/ WITH THE REST OF THE SDK, not beside the modules that use
 * it. A header under `bases/` is reachable only by a relative path, and the one
 * cross-directory user there had to write `#include "../unp/scfind.h"` - which
 * says the file is in the wrong place. What a module may include is the SDK,
 * and this is part of it.
 *
 * WHAT IT DOES. A run leaves two kinds of thing: an IMAGE - a PE or ELF a stub
 * assembled - and SURPLUS, pages it decompressed into the heap, made
 * executable, or simply wrote. They are one program, so they come out as ONE
 * object: the image reconstructed, and the surplus folded in as extra sections
 * past its end, each keeping the guest address it was lifted from in its name.
 *
 * Handing each region over separately is what this replaces, and it read
 * badly: a row of anonymous blobs beside the file - `emu:image@0x400000`,
 * `emu:exec@0x20002000` - every one of them re-parsed from nothing by whoever
 * looked at it, and none of them saying which program they belonged to.
 *
 * AND WHEN THERE IS NO IMAGE, THE SURPLUS IS THE RESULT. A stub that never
 * assembles a PE - a shellcode decoder, a packer that runs its payload from the
 * heap - leaves only surplus, and then that is what was recovered rather than a
 * leftover beside something better. It goes out raw, one child per region.
 */

#ifndef KOF_EMU_HARVEST_H
#define KOF_EMU_HARVEST_H

#define EH_PAGE   0x1000u
#define EH_MAX    64u      /* regions one run may hand over */

/*
 * WHERE THE PARENT IS LOADED, read out of its first program header.
 *
 * By hand rather than through kof_elf(), because this file is included by
 * modules that target several formats and kof_elf() casts ctx->file_header -
 * the ABI allows more than one target only for a module that never casts. Every
 * field here is a plain read of the object's own bytes.
 *
 * Answers 0 when the object is not an ELF this can read, which is also the
 * answer for "no program headers", and the caller treats that as "not the
 * program's own image".
 */
static uint64_t eh_elf_base(const struct kof_obj_ctx *ctx)
{
	uint64_t phoff;

	if (ctx->format != KOF_FMT_ELF)
		return 0;
	if (kof_u32(0) != 0x464c457fu)          /* \x7fELF, little endian */
		return 0;
	if (kof_u8(4) == 2) {                   /* ELFCLASS64 */
		phoff = kof_u64(0x20);
		if (!phoff || !kof_u16(0x38))   /* e_phnum */
			return 0;
		return kof_u64(phoff + 0x10);   /* p_vaddr */
	}
	phoff = kof_u32(0x1c);
	if (!phoff || !kof_u16(0x2c))
		return 0;
	return kof_u32(phoff + 0x08);
}

static uint64_t eh_up(uint64_t n)
{
	return (n + (EH_PAGE - 1u)) & ~(uint64_t)(EH_PAGE - 1u);
}

/*
 * Fold what a run left into objects. `n` is what kunp_emu_run answered.
 * Answers how many objects were produced.
 */
static uint32_t eh_fold(const struct kof_obj_ctx *ctx, uint32_t n)
{
	uint64_t va[EH_MAX], len[EH_MAX];
	uint32_t kind[EH_MAX];
	uint32_t i, img = EH_MAX, made = 0;
	uint64_t total, at;

	if (!n)
		return 0;
	if (n > EH_MAX)
		n = EH_MAX;

	for (i = 0; i < n; i++) {
		if (!kunp_emu_region(i, &va[i], &len[i], &kind[i])) {
			len[i] = 0;
			continue;
		}
		if (kind[i] == KOF_EMU_RGN_IMAGE && img == EH_MAX)
			img = i;
	}

	/*
	 * ---- NO IMAGE: THE SURPLUS IS WHAT WAS RECOVERED --------------------
	 *
	 * AND IT IS ASKED FOR A HEADER, because bytes are not a file. What a
	 * decoder leaves is machine code with nothing in front of it: nothing
	 * identifies it, no region partition is possible, and every rule scoped
	 * to CODE is silently inapplicable. Measured on msfvenom's `poly`, the
	 * run leaves one 4096-byte page and it came out as "unrecognised, 4096
	 * bytes".
	 *
	 * TWO CASES, AND THE ADDRESS TELLS THEM APART.
	 *
	 *   THE PAGE IS THE PROGRAM'S OWN IMAGE - it starts at the address the
	 *   parent is loaded at. Then it already HAS a header; what it has is a
	 *   header the run damaged. `poly` overwrites the first sixteen bytes
	 *   of its own e_ident with a pointer, so the page carries a correct
	 *   program header and a correct payload behind a magic that is gone.
	 *   The content is written from offset 0 and the engine's header lands
	 *   on top of the broken one.
	 *
	 *   THE PAGE IS SOMEWHERE ELSE - the heap, a mapping the stub made.
	 *   Then it is payload with no header at all and the header goes IN
	 *   FRONT of it, with the load address chosen so the payload still sits
	 *   at the address it ran at.
	 *
	 * ELF ONLY. A PE header is written from the parent's own header as a
	 * template, and a parent that is not a PE has none to lend - see
	 * `as_format`. A surplus page of a PE goes out raw, as it always did.
	 */
	if (img == EH_MAX) {
		uint64_t base = eh_elf_base(ctx);
		uint64_t hdr = ctx->arch == KOF_ARCH_X86_64 ? KUNP_HDR_ELF64
							    : KUNP_HDR_ELF32;

		for (i = 0; i < n; i++) {
			int is_image;

			if (!len[i])
				continue;
			if (ctx->format != KOF_FMT_ELF) {
				kunp_rcstruct_name(0, 0);
				if (!kunp_emu_take(i))
					break;
				kunp_rcstruct_done();
				made++;
				continue;
			}
			is_image = base && va[i] == base;
			if (is_image && len[i] <= hdr)
				continue;       /* nothing behind the header */
			if (kunp_rcstruct_section(".text", hdr,
						  is_image ? len[i] - hdr
							   : len[i],
						  KUNP_PERM_R | KUNP_PERM_W |
						  KUNP_PERM_X,
						  KOF_SECF_CODE |
						  KOF_SECF_REBUILT) < 0)
				break;
			kunp_rcstruct_as(KOF_FMT_ELF, ctx->arch,
					 is_image ? va[i] : va[i] - hdr);
			if (!kunp_rcstruct_image())
				break;
			kunp_rcstruct_entry(hdr);
			if (!kunp_rcstruct_at(is_image ? 0u : hdr) ||
			    !kunp_emu_take(i))
				break;
			kunp_rcstruct_done();
			made++;
		}
		return made;
	}

	/*
	 * ---- AN IMAGE, WITH THE SURPLUS FOLDED INTO IT ----------------------
	 *
	 * The span is declared as one range because that is all that is known
	 * before the bytes are in place; the image's own layout replaces it
	 * once they are, and the surplus is declared after that.
	 */
	total = eh_up(len[img]);
	for (i = 0; i < n; i++)
		if (i != img && len[i])
			total += eh_up(len[i]);

	if (kunp_rcstruct_section("", 0, total, KUNP_PERM_R,
				  KOF_SECF_DATA | KOF_SECF_REBUILT) < 0)
		return 0;
	if (!kunp_rcstruct_image())
		return 0;
	if (!kunp_rcstruct_at(0) || !kunp_emu_take(img))
		return 0;

	/*
	 * THE IMAGE'S OWN HEADER SAYS WHAT ITS SECTIONS ARE, and this is the
	 * only point at which that can be asked - the bytes had to be in place
	 * first. It replaces the one span declared above, and cuts the child
	 * back to where the image ends.
	 *
	 * ASKED BEFORE THE SURPLUS IS WRITTEN, AND THAT ORDER IS THE WHOLE
	 * POINT. The cut is to the IMAGE's end, so anything already written
	 * behind it is thrown away: the first version wrote the surplus first
	 * and lost every byte of it, leaving five declared sections with
	 * SizeOfRawData 0 and SEC_PAST_EOF on the child - measured on
	 * 007 Spy.exe.
	 *
	 * The answer is where to put the surplus. A region that begins MZ and
	 * carries no readable header is not a file; the span declared above
	 * stands, and the surplus goes behind the image as sized.
	 */
	at = kunp_rcstruct_layout_of_image();
	if (!at)
		at = eh_up(len[img]);

	for (i = 0; i < n; i++) {
		char nm[9];
		unsigned k;
		uint64_t pg;

		if (i == img || !len[i])
			continue;
		if (!kunp_rcstruct_at(at) || !kunp_emu_take(i))
			break;
		/*
		 * NAMED BY WHERE THE RUN PUT IT, AND BY WHICH TIME.
		 *
		 * A page lifted from 0x20002000 has no address in this file and
		 * no other tie back to the program that wrote it, so the guest
		 * page number goes in the name.
		 *
		 * AND A LETTER, BECAUSE ONE ADDRESS CAN BE HANDED OVER TWICE.
		 * A guest may make the same range executable more than once and
		 * each call leaves a snapshot; the gathering drops the ones
		 * whose bytes are identical, so two that survive are the same
		 * page at two moments - before a decode and after it. Measured
		 * on 007 Spy.exe: 0x20000000 twice, 8192 bytes each, different
		 * content, and with no letter they came out as two sections
		 * called `.e020000` that nothing could tell apart.
		 *
		 * Eight characters is all a PE section name has, and six hex
		 * digits of page plus a sequence letter is what fits. No
		 * leading dot for the same reason - the name is the whole of
		 * what is known about where these bytes came from, and a dot
		 * would cost a digit of it.
		 */
		pg = va[i] >> 12;
		nm[0] = 'e';
		for (k = 0; k < 6u; k++)
			nm[6u - k] = "0123456789abcdef"[(pg >> (4u * k)) & 0xfu];
		{
			uint32_t q, seq = 0;

			for (q = 0; q < i; q++)
				if (q != img && len[q] &&
				    (va[q] >> 12) == pg)
					seq++;
			nm[7] = (char)('a' + (seq < 26u ? seq : 25u));
		}
		nm[8] = 0;
		/*
		 * The image is flat - a run's pages are at the addresses they
		 * ran at - so the address the bytes went to is also the address
		 * they are read at, and one number serves as both.
		 */
		if (kunp_rcstruct_section(nm, at, eh_up(len[i]),
					  kind[i] == KOF_EMU_RGN_EXEC
					  ? (KUNP_PERM_R | KUNP_PERM_X)
					  : (KUNP_PERM_R | KUNP_PERM_W),
					  (kind[i] == KOF_EMU_RGN_EXEC
					   ? KOF_SECF_CODE
					   : KOF_SECF_DATA) |
					  KOF_SECF_REBUILT) < 0)
			break;
		at += eh_up(len[i]);
	}
	kunp_rcstruct_done();
	return 1u;
}

#endif /* KOF_EMU_HARVEST_H */
