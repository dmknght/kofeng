/*
 * amsi.h - the regions of one collected AMSI event.
 *
 * WHY AN EVENT HAS REGIONS AT ALL.
 *
 * A signature says WHERE to look as well as what for, and for an event those
 * are two very different places. The submitted content is attacker text: a
 * script block, a decoded command, sometimes an executable. Everything else in
 * the record is the collector's account of the submission - which process,
 * which image, when. A rule that matched "powershell.exe" without saying which
 * of the two it meant would fire on the image name of every legitimate script
 * host, forever.
 *
 * So: two regions, and they PARTITION the record. That is the contract kofsig.h
 * asks a format to keep - OR-ing any set of region bits must scan no byte twice
 * and leave none unreachable - and it is what lets a rule name both when it
 * really does mean "anywhere in the event".
 *
 * THE OBJECT IS THE REASSEMBLED EVENT, NOT ONE RECORD. A submission longer than
 * one record arrives as an event followed by continuation records, and what a
 * rule is written against is the whole of it - so whoever builds the object
 * joins them first and presents the head plus the full content. That joining
 * happens OUTSIDE the engine, in whatever holds the records; the engine is
 * handed the result and told where the content sits in it.
 *
 * A rule that saw only the first four hundred bytes would miss whatever a
 * downloader assembled past them, which is where it puts it.
 */

#ifndef KOFMOD_AMSI_H
#define KOFMOD_AMSI_H

/*
 * Bit 0 is left alone, as it is for every other format here: KOF_SCAN_ALL is
 * the mask that means "everything" and a region sharing its bit could not be
 * distinguished from it.
 */
enum kof_scan_amsi {
	/*
	 * THE COLLECTOR'S ACCOUNT: the fixed head and every string in the arena
	 * that is not the submission - the image, the command line.
	 *
	 * Facts about who submitted, not what was submitted. A rule keyed here
	 * is making a claim about the context, which is a different and usually
	 * much weaker claim than one about the content.
	 */
	KOF_SCAN_AMSI_META = 1u << 1,

	/*
	 * WHAT WAS SUBMITTED, exactly as the provider handed it over.
	 *
	 * Raw bytes, not text: it may hold NULs, it is usually UTF-16, and it
	 * may be a PE image. A literal written for it wants KOF_DEFINE_STR_WIDE
	 * far more often than KOF_DEFINE_STR - see that macro.
	 */
	KOF_SCAN_AMSI_OBJ  = 1u << 2
};

#define KOF_SCAN_AMSI_CLAIMED (KOF_SCAN_AMSI_META | KOF_SCAN_AMSI_OBJ)

/*
 * The list, so ksigbuilder's table of nameable regions is generated from this
 * header rather than copied out of it. A region added above is nameable by a
 * signature the moment it is added here - see the note on rgn_names[].
 */
#define AMSI_REGIONS(X)       \
	X(KOF_SCAN_AMSI_META) \
	X(KOF_SCAN_AMSI_OBJ)

#endif /* KOFMOD_AMSI_H */
