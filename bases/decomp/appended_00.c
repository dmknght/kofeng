/*
 * appended_00.c - yield the file an ELF was carrying as an object of its own.
 *
 * NAMED FOR THE PATTERN AND NOT FOR A CAMPAIGN. It was briefly the other way -
 * named after the samples it was written from - and that was wrong for the
 * reason the convention exists: ezuri.c and prometei_00.c are named after
 * families because the CODE is specific to them, and nothing here is. This
 * opens any file appended to any ELF, so a second campaign using the same trick
 * needs no second module and should not meet somebody else's name.
 *
 * WHAT PE ALREADY HAS AND ELF DOES NOT.
 *
 * A PE states where its own bytes end, so anything after them is the OVERLAY -
 * a region of its own, extracted by overlay.c, and every installer with an
 * archive glued on has worked that way for years. ELF states no such thing. A
 * file appended to an ELF lands in UNCLAIMED, among the alignment padding, and
 * until this module there was nothing that would open it.
 *
 * That is the gap the PoisonedRefresh samples walked through: 96% of two of
 * them is a second ELF sitting in the unclaimed gap, and the scan saw a small
 * clean-looking dropper.
 *
 *
 * WHERE IT LOOKS, AND WHY THAT IS NOT A SEARCH
 *
 * At the start of the largest unclaimed run, and nowhere else.
 *
 * Sweeping the region was the obvious design and it is the wrong one twice
 * over. It costs a pass over bytes that are usually padding - the run here is
 * 592KB - and it needs a table of magics, which is a list of the formats
 * somebody remembered. Neither is necessary: a file appended to another file
 * starts where the host file stopped, and "where the host file stopped" IS the
 * start of an unclaimed run. The offset is COMPUTED, from the region geometry
 * the parse already produced.
 *
 * A FIXED OFFSET WOULD BE WRONG and is worth saying, because in these samples
 * the payload is 0x29 bytes into the unclaimed REGION and that number is an
 * accident: the region is three runs - 40 bytes of padding, 1 byte of padding,
 * then the payload - and 40 + 1 is where the third begins once they are
 * concatenated. Another sample pads differently and the number changes. The run
 * boundary does not.
 *
 *
 * AND WHY IT DOES NOT DECIDE WHAT IT FOUND
 *
 * The user's second question was: what if the appended data is a zip, or a
 * gzip, or something else. The answer is that this module never asks. It hands
 * the run over as a child, and the child goes through the engine's own sniff
 * chain like any other object - so ELF, zip, gzip, 7z, RAR, xz, a PE, a
 * document, or bytes no format claims are all handled by the code that already
 * handles them. A magic table here would be a second, worse copy of that chain
 * that had to be edited every time a format was added.
 *
 *
 * WHAT IT COSTS. A window, so no copy and no budget. And it is reached only for
 * an object whose unclaimed run is over a page, which is 0 of 4526 clean ELF
 * objects - see bases/heur/appended_00.c for that measurement and for the reason
 * a page is the bound.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

/*
 * CONTAINER, which is what puts this in bases/decomp/ - the directory IS the
 * kind, checked by one grep in the Makefile.
 *
 * It was PACKER while this module was named for a campaign, and the two went
 * together: "a file that IS the payload, transformed" is a claim that the host
 * was hiding something. The rule that gates this refuses that claim on purpose -
 * see the note on the word "Appended" in bases/heur/appended_00.c - because a
 * self-extracting installer appends an archive without hiding anything, and the
 * measurement cannot tell the two apart.
 *
 * So the kind follows the claim: "a file that carried other files", which is
 * what was observed and all that was observed. It also stops the heuristic's
 * depth accounting counting a packer layer for an installer.
 */
/*
 * A CARVE AND NOT A CONTAINER. A container's members are declared - a zip says
 * where its entries are - and an ELF declares nothing about a file glued past
 * its last segment; this module finds it by searching. The kind is what tells
 * the analysis steps that the host is still worth examining afterwards, which a
 * container's host is not. See KOF_ANALYZE_CARVE.
 */
KOF_ANALYZE_STEP(KOF_ANALYZE_CARVE);

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_CONTENT("Appended");

/* The bound the heur rule argues for: alignment padding cannot reach a page. */
#define PAGE 4096u

/* And its entropy floor: two bits, which padding never reaches. */
#define MIN_EIGHTHS (8u * 2u)

/*
 * How far in this is willing to step over padding before giving up.
 *
 * A dropper that aligns its payload leaves zeroes in front of it, and the
 * payload is then a few bytes into the run rather than at its start. Stepping
 * over those is not a search - it stops at the first byte that is not zero, so
 * it reads at most this many bytes and never looks for anything.
 *
 * Bounded at a page for the same reason the gate is: a gap larger than that is
 * not alignment, so a run that begins with more than a page of zeroes is not a
 * padded payload - it is a run of zeroes, and windowing from the far end of it
 * would be inventing a boundary.
 */
#define SKIP_MAX PAGE

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_elf_info *e = kof_elf(ctx);
	struct kof_region_shape u;
	uint64_t off, len, skipped = 0;

	if (!e || !e->valid)
		return;
	/*
	 * AND NOT WHEN THE OBJECT'S OWN TAIL COULD NOT BE CLAIMED.
	 *
	 * The whole premise is that an unclaimed run is where the HOST FILE
	 * STOPPED - so whatever sits there came after it. That holds only while
	 * the parse can say where the host stops, and the section table is what
	 * says it: .symtab, .strtab, .comment and the debug sections are the
	 * ELF's own bytes and they are claimed as NOLOAD from that table.
	 *
	 * With the table unreadable nothing claims them, and megabytes of the
	 * file's own metadata read as an unclaimed run. Measured on one: an ELF
	 * whose header puts its section table at 11153032 in a file of 8644262
	 * - past the end - yielded a 4.2MB "carried file" that begins
	 * "GCC: (Alpine 6.4.0)", which is its own .comment.
	 *
	 * The anomalies say exactly this, and they are the parse's own answer
	 * rather than a second guess made here. A file with no section table at
	 * all is the same case: a stripped binary's tail is claimed by nothing,
	 * and an appended file cannot be told from what the linker left.
	 */
	if (e->anomalies & (KOF_ELF_ANOM_SHOFF_PAST_EOF |
			    KOF_ELF_ANOM_SEC_PAST_EOF |
			    KOF_ELF_ANOM_SECTAB_MISSING))
		return;
	if (!kof_region_shape(KOF_SCAN_ELF_UNCLAIMED, &u))
		return;
	if (u.widest < PAGE)
		return;
	/*
	 * The same floor the rule applies, and for the same reason: a run over
	 * a page that is all zeroes is a gap, and windowing it produces a child
	 * of zeroes for every module in the database to scan. Kept in step with
	 * bases/heur/appended_00.c on purpose - a gate that fired on one
	 * side and not the other would report an appended file with nothing under it,
	 * or open something nothing said was worth opening.
	 */
	if (kof_entropy_at(u.widest_off, u.widest) < MIN_EIGHTHS)
		return;

	/*
	 * AND NOT WHEN SOMETHING ELSE ALREADY OPENED THIS OBJECT.
	 *
	 * This is the generic answer to "there are bytes here nobody claimed",
	 * and a module that knows what those bytes ARE gives a better one. On a
	 * TeamTNT sample the unclaimed run is an Ezuri key and ciphertext:
	 * ezuri.c decrypts it and hands back the ELF, and this module carved
	 * the same run out again as 340052 bytes of ciphertext - a second
	 * object, from the same bytes, that nothing can read and no rule can
	 * match.
	 *
	 * Same rule emu_generic_00.c follows for the same reason: the general
	 * mechanism runs where the specific ones declined.
	 */
	if (kunp_opened_already())
		return;

	off = u.widest_off;
	len = u.widest;

	/*
	 * Step over leading zeroes, up to the bound above. Zero and not "not a
	 * magic byte": padding is zero by definition, and testing for anything
	 * else would be the format guessing this module exists to avoid.
	 *
	 * A BLOCK AT A TIME FIRST, because kof_u8 is a call through the host's
	 * content vtable - the module cannot touch the mapping - and SKIP_MAX
	 * is a page. An ELF whose appended run opens with 4096 zeroes paid 4096
	 * indirect calls to walk past padding. kof_memeq asks the same question
	 * of 64 bytes in one call, which the host answers with a memcmp.
	 *
	 * The two loops answer identically: the block loop advances only over
	 * 64 bytes that are ALL zero and only while the whole block stays
	 * inside both bounds, so it never steps anywhere the byte loop below
	 * would have stopped. Whatever it leaves - a partial block, or the
	 * first non-zero byte - the byte loop finishes exactly as before.
	 */
	{
		static const uint8_t zeros[64] = { 0 };

		while (skipped + 64u <= SKIP_MAX && len > PAGE + 64u &&
		       kof_memeq(off, zeros, 64)) {
			off += 64u;
			len -= 64u;
			skipped += 64u;
		}
	}
	while (skipped < SKIP_MAX && len > PAGE && kof_u8(off) == 0) {
		off++;
		len--;
		skipped++;
	}

	/*
	 * No bounds arithmetic beyond this. The host clips a window to what the
	 * object has, so a run that the region list and the mapping disagree
	 * about yields a shorter child rather than a read past the end - the
	 * same rule overlay.c relies on.
	 */
	kunp_rcstruct_window(off, len);
}

/*
 * IMPROVE appended-carve-1 (owner, 2026-11-01; NOTE ONLY, not reviewed yet: the owner says this carve is WRONG and the module needs review and tuning) - Sink: kof_unpack.
 * Sample: /home/dmknght/Desktop/MalwareLab/MalwareSourceCode/Linux/Rootkits/Linux.Ark.a/ark (ELF i386, dynamically linked, stripped, 18034 bytes, 29 sections declared,
 * entry 0x80484e0; two PT_LOAD of 6879 and 256 bytes, so most of the file is the tail past the loaded segments). `kofexaminer --db D --debug` says: anomalies SHSTRNDX_BAD,
 * regions HEADERS=1404 CODE=6635 DATA=256 UNCLAIMED=9739, `packer Carve:ELF?Appended`, `recovered 1 7612 bytes`, `unpacked 1 object(s)`: this module made a 7612-byte object out of it.
 * Not examined: where that object starts and ends, what it holds, and what in the tail (the section header table and the section contents lie there: SHSTRNDX_BAD) made
 * the module take it for an appended ELF. To check next: the carved bytes against the file's own sections and symbol/string tables; whether the carve should have refused a tail
 * that is the original file's own section area.
 * EXPERIMENT (owner order 2026-11-01, measured, harness /mnt/games/normtest/fix_elf_end/exp/rule.py, header parsing only; nothing in the engine changed): the ELF's own extent = the union of the
 * ELF header, the program header table, every PT_LOAD file extent, the section header table and every non-NOBITS section, each counted only when whole inside the file; logical end = its maximum.
 * What this module does today: it takes the WIDEST UNCLAIMED run ANYWHERE (not the tail), needs >= 4096 bytes and entropy >= 2 bits, skips up to 4096 leading zero bytes, and refuses only when
 * SHOFF_PAST_EOF / SEC_PAST_EOF / SECTAB_MISSING is set (SHSTRNDX_BAD is not in that list). Ark: EOF 18034, logical end by the header 15908, tail 2126: NOT equal, because the declared section
 * table (e_shoff 14748) reads as garbage (SHSTRNDX_BAD); the real table is at 14732 and the last real section ends at 18052, 18 bytes past EOF: the 2126 tail bytes are the file's own .strtab, so
 * the plain rule is a false positive on a lying table. The 7612 bytes carved are, by arithmetic 14748-7136 [Inference], [7136, 14748), entirely BEFORE the logical end: bytes of the file itself.
 * Corpus of 513 ELF (261 under MalwareSourceCode/Linux, 252 of Bazaar.2026.08): EOF == logical end 481; EOF > logical end 32 = 28 files with a lying section table but consistent PT_LOAD, 2 truncated,
 * 2 clean with a tail of 1-2 text bytes; first bytes of the 32 tails: 26 other, 6 text, none ELF/PE/ZIP/gzip/xz/UPX/zeros: NO real appended executable exists in this corpus. This module carved 3 files, all
 * false of the Ark kind (0x333MD5Hash-lnxbin 4528 bytes, bigram 13191, ark 7612; all SHSTRNDX_BAD); 29 files have a tail by the rule and are not carved (flag, or tail under 4096); on 4 synthetic files with an
 * appended ELF / noise / zeros the module carves exactly the appended part and nothing for 8000 zeros or 100 bytes. 176 of 513 files have section contents AFTER the section header table: a rule must
 * not assume the table is last. Every file with a tail of 264 bytes or more carries a flag on the section/program tables: the rule is trustworthy only when the tables are NOT flagged (SHSTRNDX_BAD,
 * SEC_PAST_EOF, SHOFF_PAST_EOF, SECTAB_MISSING, SEG_PAST_EOF, PHOFF_PAST_EOF); when flagged the tail is the file's own or the file is truncated. Not measured: a gap of a page or more in the MIDDLE of a file
 * (this module would carve it, the rule says nothing is appended). If a fix is ordered: add SHSTRNDX_BAD (and SEG/PHOFF_PAST_EOF) to the refusal list (alone it removes the 3 false carves and changes
 * no correct case measured) and replace the widest-UNCLAIMED-anywhere choice by [logical end, EOF) with the logical end computed once in libgenome/genotype/image. */
