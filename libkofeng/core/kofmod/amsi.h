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

/* For kof_streq_, which every from_name helper in this directory uses. */
#include <kofmod/kofsig.h>

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

/*
 * WHAT WAS SUBMITTED, AS A SUBTYPE - the third prefilter axis, beside format
 * and architecture. See ctx->subtype in kofsig.h for why this is an axis rather
 * than two more formats.
 *
 * There are two things a provider hands to AMSI and they have nothing in
 * common but the API they arrive through.
 *
 * One is an EXECUTABLE IMAGE: a .NET assembly on its way to Assembly.Load, a
 * native image a loader is about to map. It is a file, it has a file's
 * structure, and every rule ever written for that format applies to it - which
 * is why the parse declares it as a child rather than only marking it here.
 *
 * The other is COMMAND TEXT: a PowerShell script block, a command line, a WSH
 * script, a VBA macro body. Text a host is about to execute, and the place
 * where deobfuscation work belongs - which is a completely different kind of
 * module from anything that reads a file header.
 *
 * MARKING WHICH ONE SAVES THE WORK, and that is the point of putting it on this
 * axis. Measured on a real trace: 30 submissions, 2 images, 28 command text. A
 * deobfuscator that targets COMMAND is not offered the 2, and an image rule is
 * not offered the 28, and neither has to open an object to find that out.
 *
 * UNKNOWN is what a submission with no content is, and it is a real answer
 * rather than a failure: a provider may submit an empty buffer.
 */
#define KOF_AMSI_KIND_LIST(X)                                                \
	X(KOF_AMSI_UNKNOWN, 0)                                               \
	X(KOF_AMSI_IMAGE,   1)   /* an executable, declared as a child too */ \
	X(KOF_AMSI_COMMAND, 2)   /* script or command text about to run */

enum kof_amsi_kind {
#define KOF_AMSI_KIND_X(name, val) name = val,
	KOF_AMSI_KIND_LIST(KOF_AMSI_KIND_X)
#undef KOF_AMSI_KIND_X
	KOF_AMSI_KIND_COUNT = 3
};

/* The identifier a signature source writes, to its value - the same shape
 * kof_pe_image_from_name has, so the build tool asks this header rather than
 * carrying a copy of the list. */
static inline int kof_amsi_kind_from_name(const char *s, uint32_t *out)
{
#define KOF_AMSI_X_FROM(name, val)                                           \
	if (kof_streq_(s, #name)) { *out = (uint32_t)(val); return 1; }
	KOF_AMSI_KIND_LIST(KOF_AMSI_X_FROM)
#undef KOF_AMSI_X_FROM
	return 0;
}

#endif /* KOFMOD_AMSI_H */
