/*
 * kofobjfmt.h - what an object is: the format enum, the target axis a module
 * declares against, and the names of formats and architectures.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFOBJFMT_H
#define KOFENG_KOFOBJFMT_H

#include <stdint.h>
#include "cell.h"

/*
 * What the object is. Selects which format header's view applies, if any.
 *
 * Named for the format and not for where the bytes came from, because those are
 * different questions and only the first one is a module's business. An ELF in a
 * process image and an ELF on disk are the same format; the byte accessors
 * abstract over the source, so a module reading offsets works on either without
 * knowing which it got. Where they genuinely differ - a memory image has no
 * overlay, a file has no materialised .bss - the collector normalises coordinates,
 * and both answers are correct for the thing actually being scanned.
 *
 * Combining the two axes into values like MEM_ELF and FILE_ELF would multiply the
 * enum by source and force a new value per format for every source.
 */
enum kof_format {
	KOF_FMT_UNKNOWN = 0,
	KOF_FMT_ELF     = 1,
	KOF_FMT_PE      = 2,
	KOF_FMT_MACHO   = 3,
	KOF_FMT_SCRIPT  = 4,
	KOF_FMT_TEXT    = 5,
	KOF_FMT_GZIP    = 6,

	/*
	 * A document, and which encoding it arrived in.
	 *
	 * Two values rather than one with a sub-kind field, because the two are not
	 * one format written two ways - they differ in where the document's own
	 * structure lives. A DOCOLE holds its parts as streams INSIDE one object, so
	 * the parts are regions of it. A DOCZIP holds its parts as separate archive
	 * entries, so the parts are child objects and the discriminator is an entry
	 * name. A module written for one cannot run against the other, and format is
	 * what the prefilter rules on - so they are separate formats.
	 *
	 * DOCOLE is CFB, which is also what MSI and Outlook messages are. The name is
	 * narrower than the container on purpose: a format id is a prefilter gate,
	 * not the identity of a parser, so a future KOF_FMT_MSI can share every line
	 * of the CFB parse and still be ruled in and out on its own.
	 */
	KOF_FMT_DOCOLE  = 7,
	KOF_FMT_ZIP     = 8,
	KOF_FMT_DOCZIP  = 9,

	/*
	 * An archive with no compression in it at all.
	 *
	 * Its own format rather than a kind of ZIP because nothing about reading it
	 * is shared: no central directory, no methods, no end record - a stream of
	 * fixed blocks. It is here almost entirely because of what it arrives inside:
	 * 268 of 295 gzip files in the measured collection hold one.
	 */
	KOF_FMT_TAR     = 10,

	/*
	 * The archive that compresses its own file list.
	 *
	 * Its own format because nothing about reading it resembles the others: the
	 * layout is four numbers in a 32 byte header, the entries are described in a
	 * second header at the far end of the file, and that second header is itself
	 * put through a coder - so a parser can describe the container and not its
	 * contents. See sevenzip.h.
	 */
	KOF_FMT_7Z      = 11,

	/*
	 * The largest container in this collection by bytes, and two formats behind
	 * one magic.
	 *
	 * RAR keeps its file list in the clear the way a zip does - so names, sizes,
	 * ratios and the encryption flag all cost nothing - but compresses content
	 * with an algorithm this engine does not implement. RAR3 and RAR5 share the
	 * first six bytes and nothing else; which one an object is sits in
	 * ctx->subtype. See rar.h.
	 */
	KOF_FMT_RAR     = 12,

	/*
	 * The container that came free with a decoder written for another one.
	 *
	 * xz codes its blocks with LZMA2, which this engine grew in order to reach
	 * 7z content - so what was missing was never the decoding, only the twelve
	 * bytes at each end that say where the blocks are. See xz.h.
	 */
	KOF_FMT_XZ      = 13,

	/*
	 * The first format here that is syntax rather than structure.
	 *
	 * RTF has no offsets: where anything sits is decided by reading forward
	 * through braces and control words. What makes it worth reading is what it
	 * carries - an embedded object arrives hex encoded after \objdata, and
	 * decoding it usually yields a compound file this engine already opens.
	 * See rtf.h.
	 */
	KOF_FMT_RTF     = 14,
	KOF_FMT_PDF     = 15,

	/*
	 * WHAT A DOCUMENT DRAWS WITH, AND WHY THESE TWO ARE FORMATS AT ALL.
	 *
	 * A format is one value per kind of thing a rule can be written about -
	 * that is the line this enum is drawn on, and it is why an event is in
	 * here. A rasteriser program and a compressed bitmap are both things a
	 * rule can be written about: a malicious OpenType file is a real
	 * object, and so is a JBIG2 stream aimed at a decoder bug.
	 *
	 * THEY EXIST SO THAT NOTHING OPENS THEM UNTIL SOMETHING WANTS TO, and
	 * that follows from what a format already does rather than from any new
	 * policy. A format GATES: a module is offered an object only when
	 * its target list names its format. So a child declared KOF_FMT_FONT with
	 * no rule in the database targeting fonts is a child that will be
	 * produced - inflated, copied, charged to the budget - and then handed
	 * to nobody. The gate has already said no; fmt_wanted below is that
	 * same no, asked before the work instead of after it.
	 *
	 * THE DAY SOMEBODY WRITES THE RULE, the work starts happening again,
	 * with no engine change and no policy table anywhere: one
	 * KOF_TARGET_FORMAT(KOF_FMT_FONT) in a signature source is the whole
	 * of it. That is the difference between this and a skip list - a skip
	 * list has to be edited by whoever notices, and this is answered by the
	 * database that would have done the looking.
	 *
	 * MEASURED, on an ordinary 302KB document: 267KB of it - 88% - is font
	 * programs, and every byte was being inflated and scanned for rules
	 * that could not match. Images are the same argument and larger still;
	 * see KOF_SCAN_PDF_RESOURCE_IMAGE in kofmod/pdf.h for that measurement.
	 *
	 * A PARSER DECLARES THESE, and only from its own structure - /Subtype
	 * /Image says it, a /FontFile reference says it. Where the structure
	 * does not say, the answer stays KOF_FMT_UNKNOWN, which means "I will
	 * not say" and is always opened. Guessing here would hide a payload by
	 * calling it a picture, which is the one mistake this must not make.
	 */
	KOF_FMT_IMAGE   = 16,
	KOF_FMT_FONT    = 17,

	/*
	 * bzip2, AND THE LAST VALUE THE AXIS HAD.
	 *
	 * One stream, one member, four bytes of wrapper - there is less to parse
	 * here than in any other container, and it is a format anyway for the
	 * reason every container is: format is what the prefilter rules on, so
	 * without a value nothing targets a .bz2 and the bytes inside it are
	 * reached by nobody. Measured on the exploit-db binary corpus: 14 of
	 * 2335 files are a bare BZh stream and every one was skipped with "no
	 * module targets the format".
	 *
	 * WHAT IT COSTS, stated because the next person to add a format needs to
	 * know before they start: this is 18, KOF_FMT_COUNT is now 19, and
	 * KOF_TARGET_FIRST_EVENT moved to 19 to match - which puts it exactly on
	 * KOF_EVT_AMSI_SCAN. There is no twentieth value. A format after this
	 * one needs the axis WIDENED - the target is a uint32 mask in the pack
	 * (see dbpacker.c) - and that is a pack format change rather than an
	 * enumerator.
	 */
	KOF_FMT_BZIP2   = 18,

	/*
	 * CHM - the HTML Help archive, and the first format added after the
	 * axis stopped being bits.
	 *
	 * It takes 23 and not 19 because nineteen through twenty-two are event
	 * verbs, which are numbered into records already written and do not
	 * move. That is all the old "line" amounts to now: four values already
	 * spoken for, rather than a half of the axis that could run out. See
	 * chm.h for what the format is and what this build does not do with it.
	 */
	KOF_FMT_CHM     = 23,

	/* The Microsoft Cabinet - see cab.h for why this one is worth having
	 * while the older archives beside it in the corpus are not, yet. */
	KOF_FMT_CAB     = 24,

	/* LHA/LZH - see lha.h for why a format from 1988 is worth a value. */
	KOF_FMT_LHA     = 25,

	/* ARJ - see arj.h; its self extractor is why the bytes still turn up. */
	KOF_FMT_ARJ     = 26,

	/*
	 * A Windows shell link - see lnk.h. Not an executable and not a
	 * container: a small structure whose payload is a command line the
	 * shell runs.
	 */
	KOF_FMT_LNK     = 27,

	/*
	 * A registry script - see reg.h. Text, and parsed for the same
	 * reason a shell link is: where a string sits is what it means.
	 */
	KOF_FMT_REG     = 28,

	/*
	 * ONE COLLECTED EVENT, not a file.
	 *
	 * The object is one collected event - what a collector saw happen, with
	 * the submitted content inside it.
	 *
	 * The engine does not read that record's layout and cannot: it belongs
	 * to libkoforbit, which sits outside. What reaches a parser here is a
	 * buffer plus the caller's word for where the content is - see
	 * amsi_parse.h. It is a format here for the same
	 * reason every other value is: format is what the prefilter rules on, so
	 * a rule written about a script submission is never offered an ELF and
	 * an ELF rule is never offered an event.
	 *
	 * It is DECLARED, NOT SNIFFED. Every format above is recognised from its
	 * bytes; a record has no magic, and guessing "this 512 bytes is an
	 * event" from plausible-looking fields would claim arbitrary data as
	 * one. Whoever has the record knows what it is - the client that read it
	 * off the channel, the viewer that opened the log - and says so.
	 *
	 * AMSI rather than EVENT because the regions are AMSI's: a submission
	 * and the fields around it. A verb with a different shape worth writing
	 * rules against gets its own value and its own regions, the same way
	 * DOCOLE and DOCZIP are two formats rather than one with a sub-kind.
	 * A NetRecv rule, for instance, is a comparison of ADDRESSES rather
	 * than a search through bytes, so it wants a different shape again.
	 *
	 *
	 * KOF_EVT_ AND NOT KOF_FMT_, AND THE NAME IS NOT COSMETIC.
	 *
	 * This sits in enum kof_format because format is the axis the prefilter
	 * rules on - one value per kind of thing a rule can be written about,
	 * so an event is never offered to an ELF module and an ELF is never
	 * offered to this one. That is the mechanism and it does not change.
	 *
	 * But what an author DECLARES is the kind of event, so that is what
	 * they write. A signature reading KOF_TARGET_EVENT(KOF_EVT_AMSI) says
	 * what it is about; the same rule spelled as a "format" would be asking
	 * an author to call a submission a file format.
	 *
	 * NOT TO BE CONFUSED WITH KOF_EVT_AMSI_SCAN, which is a VERB - what one
	 * record says happened. This is what a RULE targets. They are one to
	 * one today and they are not the same axis: verbs are the collector's
	 * vocabulary and grow as it learns event ids, targets grow only when
	 * there is a shape worth writing rules against.
	 *
	 * WHO MAPS ONE TO THE OTHER is the CLIENT, not the engine. A verb is
	 * libkoforbit's vocabulary and this is the engine's; whoever holds a
	 * record and wants it scanned knows both, and it is the only side that
	 * does. The engine deliberately cannot name a verb - see the note in
	 * amsi_parse.h on which way that arrow points.
	 */
	KOF_EVT_AMSI    = 19,

	/*
	 * A RUNNING PROCESS, as libkoforbit/antarc reads it out of /proc.
	 *
	 * Its own target rather than a subtype of anything, because the SHAPE
	 * of a rule about one is unlike every other row here: it is a
	 * comparison of scalars and of two kernel strings, not a search through
	 * bytes. See kofmod/proc.h.
	 *
	 * TWENTY-TWO, which is KOF_EVT_PROC_INFO - the value IS the verb, so
	 * the byte a client filters records on is the byte the prefilter rules
	 * modules on. Above KOF_TARGET_FIRST_EVENT, asserted below with the
	 * other one.
	 */
	KOF_EVT_PROC    = 22,

	/*
	 * One past the highest FILE FORMAT value, so a host can size a
	 * per-format table. Not a format: nothing is ever this.
	 *
	 * The event targets below continue the SAME numbering, so this is not
	 * the width of the target axis - KOF_TARGET_COUNT is. A table indexed
	 * by target value wants that one.
	 */
	KOF_FMT_COUNT   = 29
};

/*
 * THE TARGET AXIS: ORDINARY NUMBERS, NOT BITS.
 *
 * A target is what a module declares it is for - a file format, or the verb of
 * a collected event. The values are plain ordinals: KOF_FMT_ZIP is 8, and 8
 * means the ninth target, not the ninth bit of anything.
 *
 * IT WAS BITS, and that is why this note exists. A module's target was a uint32
 * MASK, because a module may be for several formats at once - the zip unpacker
 * is for ZIP and DOCZIP both. One bit per target made the number of things this
 * engine could EVER target equal to the width of a word: nineteen file formats
 * and four event verbs share the axis, so the twenty-fourth target could not be
 * added at all. Adding bzip2 spent the last value under the old scheme, and the
 * next format would have needed the mask widened, which is a pack format
 * change to buy thirty-two more of something that will run out again.
 *
 * So a module carries a LIST OF IDS and a count of them - see n_target in
 * dbloader.h. The count is what makes it safe: a reader knows exactly how many
 * bytes of the row mean anything, so a row cannot be read into the next one.
 * Multi-target modules stay cheap because the hot path never walks the list -
 * the loader builds an inverted index from target id to modules and the scan
 * looks up the bucket for the object in hand.
 *
 * NUMBERS ARE ASSIGNED IN ORDER AND NOTHING IS RESERVED. A new file format
 * takes the next free value, which is KOF_TARGET_COUNT, and raises it. There is
 * no line between the formats and the verbs any more, because there is nothing
 * to ration: the axis is as wide as the byte that holds an id.
 *
 * WHAT STILL DOES NOT GET A VALUE OF ITS OWN: a file type that shares another's
 * HEADER AND VIEW. The subtype axis is for exactly that - ctx->subtype - and it
 * is what tells a .so from an executable, php from python, and would tell two
 * document kinds apart that a parser reads identically. A second format value
 * for the same bytes buys a name and costs a parse, a view struct and a row in
 * every table that lists formats. Spend a format when the PARSE differs; spend
 * a subtype when only the KIND does.
 */
/*
 * RAISED FOR LNK (27) AND REG (28), AND NOT RAISING IT WAS A CRASH.
 *
 * This is the width of every table indexed by a target value, and the one that
 * matters most is kof_scanner.view[KOF_TARGET_COUNT] - the per-format parse
 * views. A format numbered 27 with the count left at 27 writes its view
 * POINTER one past the end of that array, over whatever follows it in the
 * scanner. Nothing complains: the parse works, the scan reports correctly, and
 * the corruption is only read later.
 *
 * Measured: one .reg scanned alone was fine and two in a row segfaulted,
 * writing to address 0x7B on the second. That is the shape of this mistake -
 * the damage is done by the first object and collected by a later one, so the
 * failure points at the wrong file and at the wrong pass.
 *
 * The note above says a new format "takes the next free value, which is
 * KOF_TARGET_COUNT, and raises it". Both halves are the instruction.
 */
#define KOF_TARGET_COUNT 29u

/*
 * How many targets one module may name.
 *
 * Fifteen, which with the count byte makes a sixteen byte row in the pack. The
 * widest module in the tree names three (KOF_FMT_ELF | KOF_FMT_PE |
 * KOF_FMT_UNKNOWN); the widest a person can produce from the editor is the
 * "Archives" group, which is eight. A module that wants more than fifteen wants
 * KOF_FMT_ANY, and the builder says so rather than truncating - a silently
 * shortened list is a rule narrower than its source, with nothing printed.
 */
#define KOF_TARGET_LIST_MAX 15u

/*
 * WHERE EVENT VERBS SIT TODAY, as a fact rather than as a boundary.
 *
 * An event target's value IS its verb - KOF_EVT_AMSI is KOF_EVT_AMSI_SCAN, the
 * same number - so the byte a client filters records on is the byte the
 * prefilter rules modules on, and the two cannot drift apart because they are
 * one number. That ties the verbs to values already written into stored
 * records, which is why they are not renumbered: nineteen through twenty-two
 * are theirs and a file format does not take one.
 *
 * It is no longer a CEILING on anything. Before, everything below this belonged
 * to formats and everything above to verbs, and the format half was full. Now
 * the next format takes the next free number - twenty-three - and verbs keep
 * what they have. The assert below is the whole of the rule that remains.
 */
#define KOF_TARGET_FIRST_EVENT 19u

/* The rule that no format takes a verb's value is checked per row, beside
 * KOF_TARGET_LIST - it needs the list, which is declared further down. */
_Static_assert(KOF_TARGET_COUNT >= KOF_FMT_COUNT,
	       "the axis must cover every file format");
_Static_assert(KOF_TARGET_LIST_MAX >= 8u,
	       "the editor can name eight formats in one rule");


/* strcmp, spelled out: this header is included by rule sources that get no
 * libc, and one identifier comparison does not justify the dependency. */
static inline int kof_streq_(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

/*
 * Names for the two common enums, next to the enums themselves.
 *
 * Here because more than one place needs them and they are the only correct spelling:
 * a finding is labelled with them and so is a fact dump, and two copies drift. They
 * were duplicated in the scanner and in the examiner before this.
 *
 * Inline rather than a .c file: they are switch statements over an enum this header
 * already declares, so anything that has the enum has all it needs.
 */
/*
 * THE WAY BACK: the identifier a signature source writes, to its value.
 *
 * The sibling of kof_arch_from_name and kof_maltype_from_name, and it was the
 * one missing. Its absence had a cost that was not obvious: the database
 * builder needed format identifiers resolved, could not ask the engine, and
 * so read this header with sed - a shell regex over C source, learning enum
 * values by matching "KOF_FMT_\([A-Z0-9_]*\) *= *\([0-9]*\)". That works
 * until a value is written as an expression, a comment mentions one, or the
 * enum is reformatted, and it fails by producing a WRONG MASK rather than an
 * error.
 *
 * KOF_FMT_ANY is not here. It is not a format, it is every format at once, and
 * the caller that accepts it has to turn it into a mask rather than a value.
 */
/*
 * THE TARGETS, ONCE.
 *
 * Written as a macro rather than repeated, for the reason KOF_ARCH_LIST gives
 * and for one this file has already paid: the identifier, the display word and
 * the value were spelled out in three places here and a FOURTH in kofeditor,
 * which the editor's own comment called "the THIRD hand copy ... the one
 * nothing checks" after two formats went missing from it silently. A rule that
 * targeted an image was written narrower than its source said, and nothing
 * failed.
 *
 * Three fields: the identifier a signature writes, the value it has, and the
 * word a finding prints. The value is repeated beside the enumerator on
 * purpose - it is checked against it below, so this list cannot drift from the
 * enum without the build stopping.
 */
/*
 * WHAT KIND OF THING A TARGET IS, as the fourth column.
 *
 * Not a taxonomy for its own sake: two tools were grouping formats by hand and
 * both had to be edited whenever one was added - the viewer's format menu
 * silently lost bzip2 until somebody noticed it missing from a list of
 * archives. A group belongs beside the format for the same reason the word
 * does.
 *
 * COARSE ON PURPOSE. This answers "where would a reader look for it", which is
 * a menu and a summary line. It is NOT what decides which pack a module is
 * written into - ksigbuilder's buckets are finer (one per executable format)
 * and split DOCZIP the other way, because a pack is about which modules share
 * a prefilter and not about how a person browses.
 */
enum kof_format_group {
	KOF_FGRP_RAW = 0,     /* nothing claimed it */
	KOF_FGRP_EXEC,        /* an image a loader runs */
	KOF_FGRP_SCRIPT,      /* meant to be interpreted */
	KOF_FGRP_TEXT,        /* readable, and claiming nothing more */
	KOF_FGRP_DOC,         /* a document, whatever it is built out of */
	KOF_FGRP_ARCHIVE,     /* carries files that were separately there */
	KOF_FGRP_MEDIA,       /* pixels or glyphs */
	KOF_FGRP_EVENT        /* not a file at all - see KOF_EVT_AMSI */
};

#define KOF_TARGET_LIST(X)                                        \
	X(KOF_FMT_UNKNOWN,  0, "Raw",     KOF_FGRP_RAW)           \
	X(KOF_FMT_ELF,      1, "ELF",     KOF_FGRP_EXEC)          \
	X(KOF_FMT_PE,       2, "PE",      KOF_FGRP_EXEC)          \
	X(KOF_FMT_MACHO,    3, "MachO",   KOF_FGRP_EXEC)          \
	X(KOF_FMT_SCRIPT,   4, "Script",  KOF_FGRP_SCRIPT)        \
	X(KOF_FMT_TEXT,     5, "Text",    KOF_FGRP_TEXT)          \
	X(KOF_FMT_GZIP,     6, "Gzip",    KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_DOCOLE,   7, "DocOLE",  KOF_FGRP_DOC)           \
	X(KOF_FMT_ZIP,      8, "Zip",     KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_DOCZIP,   9, "DocZip",  KOF_FGRP_DOC)           \
	X(KOF_FMT_TAR,     10, "Tar",     KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_7Z,      11, "7z",      KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_RAR,     12, "RAR",     KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_XZ,      13, "xz",      KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_RTF,     14, "RTF",     KOF_FGRP_DOC)           \
	X(KOF_FMT_PDF,     15, "PDF",     KOF_FGRP_DOC)           \
	X(KOF_FMT_IMAGE,   16, "Image",   KOF_FGRP_MEDIA)         \
	X(KOF_FMT_FONT,    17, "Font",    KOF_FGRP_MEDIA)         \
	X(KOF_FMT_BZIP2,   18, "bzip2",   KOF_FGRP_ARCHIVE)       \
	X(KOF_EVT_AMSI,    19, "AMSI",    KOF_FGRP_EVENT)         \
	X(KOF_EVT_PROC,    22, "Process", KOF_FGRP_EVENT)         \
	X(KOF_FMT_CHM,     23, "CHM",     KOF_FGRP_DOC)           \
	X(KOF_FMT_CAB,     24, "CAB",     KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_LHA,     25, "LHA",     KOF_FGRP_ARCHIVE)       \
	X(KOF_FMT_ARJ,     26, "ARJ",     KOF_FGRP_ARCHIVE)      \
	/*
	 * SCRIPT, and the group is a judgement worth stating. A .lnk is not
	 * text and nothing interprets it as a language - but KOF_FGRP_SCRIPT
	 * is "meant to be interpreted", and what the shell does with a
	 * shortcut is take a command line out of it and run it. ARCHIVE would
	 * claim it carries files, EXEC that a loader runs it, DOC that
	 * somebody reads it; each of those is more wrong than this.
	 */                                                             \
	X(KOF_FMT_LNK,     27, "LNK",     KOF_FGRP_SCRIPT)      \
	/*
	 * TEXT, and the group is again a judgement. A .reg is read by regedit
	 * and applied, not interpreted - there is no control flow in it and
	 * nothing runs - so SCRIPT would overstate it. What it is, is a
	 * readable file that claims nothing more, which is what TEXT says.
	 */                                                            \
	X(KOF_FMT_REG,     28, "REG",     KOF_FGRP_TEXT)

#define KOF_TARGET_X_ASSERT(name, val, word, grp)                           \
	_Static_assert((name) == (val),                                     \
		       "KOF_TARGET_LIST disagrees with the enum about " #name);
KOF_TARGET_LIST(KOF_TARGET_X_ASSERT)
#undef KOF_TARGET_X_ASSERT

/*
 * AND EVERY DECLARED TARGET IS INSIDE THE AXIS, checked one value at a time.
 *
 * KOF_TARGET_COUNT >= KOF_FMT_COUNT is asserted above and would have caught
 * nothing when both were left behind: adding LNK at 27 and REG at 28 raised
 * neither, so 27 >= 27 held while kof_scanner.view[KOF_TARGET_COUNT] was being
 * indexed at 28. The view POINTER went one and two past the end of that array,
 * over whatever follows it in the scanner. Nothing complained - the parse
 * worked and the scan reported correctly - and the damage was collected by a
 * LATER object: one .reg scanned alone was fine, two in a row segfaulted.
 *
 * So the thing that has to be true of each VALUE is asserted about each value.
 * A format added without raising the count now fails to compile, which is
 * where that mistake costs nothing.
 */
#define KOF_TARGET_X_FITS(name, val, word, grp)                             \
	_Static_assert((val) < (int)KOF_TARGET_COUNT,                       \
		       #name " is outside KOF_TARGET_COUNT - raise it");
KOF_TARGET_LIST(KOF_TARGET_X_FITS)
#undef KOF_TARGET_X_FITS

/*
 * NO FILE FORMAT MAY TAKE A VERB'S VALUE, and that is now the whole rule.
 *
 * It used to be "every format is below the line", which is stronger than the
 * axis needs and is what ran out: the line was 19, the formats had filled up to
 * it, and the nineteenth could not be added at all. What has to hold is only
 * that two different things never share one id - so a format may take any value
 * the verbs do not, and the one after CHM is 24.
 *
 * Checked per row rather than as one comparison against a count, because a
 * count only catches a format that walks INTO the band from below. The group
 * column is what says which rows are verbs.
 */
#define KOF_TARGET_X_NOCLASH(name, val, word, grp)                            \
	_Static_assert((grp) == KOF_FGRP_EVENT ||                             \
		       (val) < KOF_TARGET_FIRST_EVENT ||                      \
		       (val) > KOF_EVT_PROC,                                  \
		       #name " takes a value an event verb already has - "    \
		       "verbs are numbered into stored records and do not move");
KOF_TARGET_LIST(KOF_TARGET_X_NOCLASH)
#undef KOF_TARGET_X_NOCLASH

/* Which group a target is in, or KOF_FGRP_RAW for a value this build has no
 * row for - which is what an unclaimed object is anyway. */
static inline enum kof_format_group kof_format_group(uint8_t fmt)
{
	switch (fmt) {
#define KOF_FMT_X_GROUP(name, val, word, grp) case name: return (grp);
	KOF_TARGET_LIST(KOF_FMT_X_GROUP)
#undef KOF_FMT_X_GROUP
	default: return KOF_FGRP_RAW;
	}
}

/* The group as a word, for a menu or a summary. Plural where the row names a
 * SET of formats, which is what those rows are; "Media" is already plural and
 * "Other" names what is left rather than a group. */
static inline const char *kof_format_group_name(enum kof_format_group g)
{
	switch (g) {
	case KOF_FGRP_EXEC:    return "Executables";
	case KOF_FGRP_SCRIPT:  return "Scripts";
	case KOF_FGRP_TEXT:    return "Text";
	case KOF_FGRP_DOC:     return "Documents";
	case KOF_FGRP_ARCHIVE: return "Archives";
	case KOF_FGRP_MEDIA:   return "Media";
	case KOF_FGRP_EVENT:   return "Events";
	case KOF_FGRP_RAW:     return "Other";
	default:               return "Other";
	}
}

static inline int kof_format_from_name(const char *s, uint8_t *out)
{
#define KOF_FMT_X_FROM(name, val, word, grp)                                \
	if (kof_streq_(s, #name)) { *out = (uint8_t)(val); return 1; }
	KOF_TARGET_LIST(KOF_FMT_X_FROM)
#undef KOF_FMT_X_FROM
	return 0;
}

/*
 * The IDENTIFIER, which is what a signature source spells - "KOF_FMT_ZIP".
 *
 * The other direction of kof_format_from_name, and the one the editor needs:
 * it writes KOF_TARGET_FORMAT lines, so it needs the token rather than the
 * word a finding prints. It had a table of its own for this; now there is one
 * list and the tools ask.
 */
static inline const char *kof_format_ident(uint8_t fmt)
{
	switch (fmt) {
#define KOF_FMT_X_IDENT(name, val, word, grp) case name: return #name;
	KOF_TARGET_LIST(KOF_FMT_X_IDENT)
#undef KOF_FMT_X_IDENT
	default: return 0;
	}
}

static inline const char *kof_format_name(uint8_t fmt)
{
	switch (fmt) {
#define KOF_FMT_X_NAME(name, val, word, grp) case name: return word;
	KOF_TARGET_LIST(KOF_FMT_X_NAME)
#undef KOF_FMT_X_NAME
	/*
	 * "Raw", not "Unknown", and the two are different answers.
	 *
	 * KOF_FMT_UNKNOWN is what an object HAS when no format header claimed
	 * it - a decrypted payload, a carved blob, the image an unpacker handed
	 * back. That is a bare binary, and it is a thing a rule can be written
	 * for. "Unknown" reads as "the engine could not tell", which is the
	 * default below: a format id this build has no name for, which is a
	 * fault rather than a fact.
	 *
	 * PDF was falling through to that default and reporting Unknown, so a
	 * PDF finding and a formatless one were spelled the same in a name and
	 * in a pack's filename.
	 */
	default:             return "Unknown";
	}
}

/*
 * Short, and systematic: a letter for the family and the width.
 *
 * These end up in a finding, which is read in a log next to a path, so they are
 * kept to the width of the thing they describe rather than spelled out. x86 and x64
 * keep their conventional spellings because those are what everyone already reads;
 * the rest follow the same shape so the set can be scanned at a glance.
 */
static inline const char *kof_arch_name(uint8_t arch)
{
	switch (arch) {
#define KOF_ARCH_X_NAME(name, val, word) case name: return word;
	KOF_ARCH_LIST(KOF_ARCH_X_NAME)
#undef KOF_ARCH_X_NAME
	default: return "other";
	}
}

/*
 * The way back: the identifier a signature source writes, to its value.
 *
 * Whole names only - `s` must be the identifier and nothing more. Substring
 * matching is what broke this before, KOF_ARCH_X86 being a prefix of
 * KOF_ARCH_X86_64, so the comparison here is strcmp and the caller splits its
 * own tokens.
 *
 * Returns 1 and sets *out on a hit, 0 on an unknown name - never a sentinel
 * value, because every value in the enum is a legal architecture and there is
 * none left over to mean "no".
 */
static inline int kof_arch_from_name(const char *s, uint8_t *out)
{
#define KOF_ARCH_X_FROM(name, val, word)                                     \
	if (kof_streq_(s, #name)) { *out = (uint8_t)(val); return 1; }
	KOF_ARCH_LIST(KOF_ARCH_X_FROM)
#undef KOF_ARCH_X_FROM
	return 0;
}

#endif /* KOFENG_KOFOBJFMT_H */
