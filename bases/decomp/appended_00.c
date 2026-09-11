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
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

KOF_TARGET_FORMAT(KOF_FMT_ELF);

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

	off = u.widest_off;
	len = u.widest;

	/*
	 * Step over leading zeroes, up to the bound above. Zero and not "not a
	 * magic byte": padding is zero by definition, and testing for anything
	 * else would be the format guessing this module exists to avoid.
	 */
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
	kof_child_window(off, len);
}
