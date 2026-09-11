/*
 * appended_00.c - an ELF with a whole file appended to it: the SHAPE.
 *
 * NAMED FOR WHAT WAS OBSERVED AND NOT FOR WHAT IT MEANS. "Appended" is a
 * statement anybody can check against the file; "Stowaway", "Smuggler",
 * "Hidden" all say the bytes were CONCEALED, and the measurement does not
 * support that - a self-extracting installer appends an archive for reasons
 * that have nothing to do with hiding. A heuristic reports a shape, and the
 * word it reports under should be the shape.
 *
 * ONE RULE AND NOT TWO, WHICH IT WAS BRIEFLY. A second, narrower rule over the
 * same shape added the unclaimed RATIO and named a campaign. It is gone, and
 * the measurement below is why: the narrow form is a strict SUBSET - two more
 * AND terms on the same gate - so it found nothing the broad form misses and
 * was clean only where the broad form is already clean. Its whole value was the
 * NAME, and the name was wrong, because the shape belongs to nobody in
 * particular. Two rules kept in step by hand for no separation is a seam that
 * can only drift.
 *
 *
 * THE SHAPE
 *
 * One contiguous run of bytes that no segment, no section and no header
 * admitted to owning, larger than a page, and carrying something.
 *
 * The page is not fitted to a corpus - it is what the format allows. Unclaimed
 * bytes in an honest ELF are ALIGNMENT PADDING: the gap a linker leaves so the
 * next structure starts on a boundary, and the largest boundary anything aligns
 * to is a page. A run of 4096 bytes or more cannot be padding, because nothing
 * would be aligning to anything that far away.
 *
 * AND CARRYING SOMETHING, which is the entropy floor. A run over a page that is
 * all zeroes is a big gap and not a carried file. Two bits: padding never
 * reaches it and the thinnest real payload clears it easily.
 *
 * ON THE RUN AND NOT ON THE REGION. One of the samples has 3576 bytes of zero
 * padding in the same unclaimed region as its 31968-byte payload; over the
 * region the pair reads 4.1 bits and the payload alone reads 4.5. A gate
 * written on the region measures the padding as much as the thing it is looking
 * for.
 *
 *
 * MEASURED, on the two populations that matter:
 *
 *   0 of 4526    clean ELF objects - /usr/bin, /usr/sbin, /usr/lib,
 *                /usr/libexec on a working system. The largest single
 *                unclaimed run anywhere in them is 4095 bytes, in
 *                /usr/bin/hardlink, one byte under the page the argument above
 *                predicts. And the entropy of the unclaimed region is between
 *                0 and 1 bit in EVERY ONE of the 4526 - including the 3852 that
 *                have more than a page of it in total. Clean unclaimed is
 *                padding, without exception here.
 * 701 of 3775    malware ELF objects on hand.
 *   3 of 3       the samples this was written from.
 *
 * The entropy floor drops 22 of the 723 runs over a page: those are gaps, not
 * appended files. It costs no clean object, because none has such a run at all, and
 * it costs none of the samples - 4.5, 6.0 and 6.0 bits.
 *
 *
 * THE RATIO WAS TRIED AND IS SUBSUMED, which is worth writing down because it
 * is the obvious measurement and it looks compelling: two of the samples are
 * 96% unclaimed.
 *
 * 187 of the clean objects are more than 40% unclaimed and one is 82%, because
 * a file full of small gaps adds up. Tightened to 90% it is clean - 0 of 4526 -
 * but it then finds 6 malware objects of 3775, and EVERY ONE of those six also
 * has a run over a page. Measured on both corpora, "ratio over 90% but no run
 * over a page" is empty. As an OR term it adds nothing; as an AND term it costs
 * 701 detections down to 143 and loses the third sample, which is 45%
 * unclaimed.
 *
 * "How much" separates nothing that "in one piece" does not separate better. So
 * the rule reads `widest` and never `bytes` - and where the ratio IS worth
 * seeing, it is on the screen: the region rows in both tools carry the size,
 * the share and the entropy, which is where a supplementary number belongs.
 *
 *
 * WHY IT DOES NOT LOOK FOR A HEADER
 *
 * Deciding what the appended bytes ARE is not this rule's job. An ELF, a zip, a
 * gzip, a shell script, an encrypted blob - all of them are a file somebody
 * appended, and a rule that recognised only the magics it had been taught would
 * miss the next one. What the bytes are is answered by opening them:
 * bases/decomp/appended_00.c windows the run and the engine's own sniff
 * chain names it.
 *
 *
 * WHY IT IS NOT A VERDICT
 *
 * Appending a file to an executable is how a self-extracting installer works,
 * and how several legitimate packagers ship. None of the 4526 clean objects on
 * this system does it, which is why the rule fires at all - but "no clean
 * object here does this" is a smaller claim than "nothing legitimate does
 * this", and the difference between them is exactly a heuristic.
 */

#include <kofmod/heur.h>
#include <kofmod/elf.h>

KOF_TARGET_FORMAT(KOF_FMT_ELF);

KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
KOF_HEUR_NAME("Appended");

/*
 * OPEN WHAT THIS OBJECT CARRIES, and KEEP the finding when it does.
 *
 * The first, because the run is windowed only when some loaded rule already
 * targets the format the child will turn out to have - and the point of this
 * rule is that nobody knows what the child is yet.
 *
 * The second, because the engine drops a rule's heuristic once the object
 * produces children. That is right for a rule meaning "I could not identify
 * this" and wrong here: the child is an ordinary file that nothing fires on, so
 * the drop does not move the signal, it deletes it. Measured, before the bit
 * existed: all three samples came back clean with the carried ELF extracted.
 */
KOF_HEUR_WANT(KOF_ENG_OPEN_CARRIED | KOF_ENG_KEEP_ON_OPEN);

/* A page. See the argument at the top; it is a property of the FILES and not of
 * the machine this runs on. */
#define PAGE 4096u

/*
 * Two bits, in the eighths the engine reports.
 *
 * Padding does not reach it - the 22 malware runs this drops all measure under
 * 2.0 - and nothing real fails it: the thinnest payload among the samples is
 * 4.5. A higher floor starts costing detections (569 of 723 clear 5.0) for no
 * measured gain in precision, since clean is already empty at either.
 */
#define MIN_EIGHTHS (8u * 2u)

KOF_DEFINE_HEUR
{
	const struct kof_elf_info *e = kof_elf(ctx);
	struct kof_region_shape u;

	if (!e || !e->valid)
		return;
	if (!kof_region_shape(KOF_SCAN_ELF_UNCLAIMED, &u))
		return;
	if (u.widest < PAGE)
		return;

	if (kof_entropy_at(u.widest_off, u.widest) < MIN_EIGHTHS)
		return;

	KOF_HEUR_HIT();
}
