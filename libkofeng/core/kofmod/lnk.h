/*
 * lnk.h - a Windows shell link, which is a small binary file whose payload is
 * a command line.
 *
 * WHY A PARSER FOR A SHORTCUT. Nothing about a .lnk is executable and nothing
 * in it is compressed, so it looks like the least interesting format here. It
 * is on this list because of what it CARRIES: MS-SHLLINK gives it a
 * COMMAND_LINE_ARGUMENTS string, and the shell runs that string. A shortcut
 * whose target is powershell.exe and whose arguments are eight kilobytes of
 * base64 is a complete delivery mechanism in 4 KB of file, and the file itself
 * matches no executable signature because it is not an executable.
 *
 * It is also the format where the interesting bytes are hardest to reach by
 * accident: the arguments sit behind a variable-length shell item id list and
 * a variable-length LinkInfo, so a scanner that searched the whole file would
 * find them - and would also find them in the icon path, the working
 * directory and the description, with no way to say which. Regions are the
 * whole point of parsing it.
 *
 *
 * THE LAYOUT, from MS-SHLLINK, in the order the file has it:
 *
 *   ShellLinkHeader     76 bytes, fixed, and its size field says 76
 *   LinkTargetIDList    present when HasLinkTargetIDList
 *   LinkInfo            present when HasLinkInfo - volume, local path, UNC
 *   StringData          up to five counted strings, each present when its own
 *                       flag is set, IN THIS ORDER: NAME, RELATIVE_PATH,
 *                       WORKING_DIR, ARGUMENTS, ICON_LOCATION
 *   ExtraData           a chain of blocks, ended by one whose size is under 4
 *
 * THE ORDER OF StringData IS THE FORMAT'S AND IS NOT NEGOTIABLE. Each string
 * is a count followed by that many CHARACTERS - two bytes each when IsUnicode
 * is set, one when it is not - so a parser that guessed the order or the width
 * would read the arguments out of the middle of the working directory. There
 * is no other way to find them: nothing is offset-addressed and nothing is
 * tagged.
 *
 *
 * TWO STRUCTURES ARE OFFSET-ADDRESSED, AND THEY ARE THE ONES WORTH READING
 *
 * LinkInfo and the ExtraData chain were measured and skipped when this parser
 * was first written, on the argument that what is inside them is a rule's
 * business. Measuring 120 shortcuts off a running Windows machine said
 * otherwise, because of WHAT is in them:
 *
 *   LinkInfo, in 39 of the 120, carries LocalBasePath - a plain NUL-terminated
 *   string holding the literal target, "C:\Windows\System32\WindowsPowerShell\
 *   v1.0\powershell.exe". That is the single fact a person most wants from a
 *   shortcut, and as one opaque LINKINFO region a rule could search for it but
 *   could not say it had found THE TARGET rather than a coincidence in a
 *   volume label.
 *
 *   EnvironmentVariableDataBlock, in 65 of the 120, carries the target again
 *   as an unexpanded path. A shortcut can point at \\host\share\x.exe here
 *   while its id list and its LinkInfo look local.
 *
 *   IconEnvironmentDataBlock, in 20 of the 120, is the same structure for the
 *   ICON. A UNC path in it makes the shell authenticate outward just to DRAW
 *   the folder, and the existing ICON_UNC anomaly could not see it, because
 *   that one reads ICON_LOCATION and this is a different field.
 *
 *   TrackerDataBlock, in 39 of the 120, holds the NetBIOS name of the machine
 *   the shortcut was MADE on - which is the one field in the format that says
 *   something about where a file came from.
 *
 * So these are broken out, and the regions they become are named for what they
 * hold rather than for the structure they came from.
 *
 * BOTH ARE ADDRESSED BY OFFSET, WHICH IS NEW HERE and is why there is now an
 * overlap anomaly - see the note on KOF_LNK_ANOM_INFO_OVERLAP.
 *
 *
 * WHAT IS DELIBERATELY NOT HERE
 *
 * No shell item decoding. The LinkTargetIDList is a stack of SHITEMID
 * structures whose contents are defined by whichever shell extension wrote
 * them, and reading them means knowing the format of every one. The id list is
 * published AS A REGION so a rule can search it - the target path is usually
 * recoverable as text inside it - and nothing here claims to have understood
 * it.
 *
 * No path resolution. "Where does this shortcut point" is a question about the
 * machine, not about the file: the target may be an environment variable, a
 * known folder GUID, or a relative path from the link's own directory. The
 * bytes are handed over; deciding belongs to a rule or to a person.
 *
 * No property store decoding. PropertyStoreDataBlock was the most common block
 * in the corpus after the environment one, and it is a serialised bag of typed
 * properties keyed by GUID - a format of its own, with its own string types
 * and its own length rules. It stays inside the EXTRA region, which is what
 * that region is for.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KOFENG_LNK_H
#define KOFENG_LNK_H

#include <stdint.h>

#include <kofmod/kofsig.h>

#define KOF_LNK_INFO_VERSION 2

/*
 * THE REGIONS, and every string gets its own because a rule wants to say WHICH
 * string it matched in. "cmd.exe in the arguments" and "cmd.exe in the
 * description" are different statements and a single BODY region could make
 * neither.
 *
 * UNCLAIMED KEEPS BIT 10 even though the six regions added after it have
 * higher numbers, so the list below is not in bit order. A region bit is what
 * a compiled rule stores; renumbering one silently repoints every rule that
 * named it. Reading the list out of order once is the cheaper of the two.
 */
enum kof_scan_lnk {
	KOF_SCAN_LNK_HEADER    = 1u << 1,  /* the fixed 76 bytes */
	KOF_SCAN_LNK_IDLIST    = 1u << 2,  /* LinkTargetIDList, undecoded */
	/*
	 * What is left of LinkInfo once the four below are taken out of it:
	 * its fixed header, and any padding or undecoded tail. A file whose
	 * LinkInfo could not be decoded at all has the whole structure here,
	 * which is what this region meant before there was anything else.
	 */
	KOF_SCAN_LNK_LINKINFO  = 1u << 3,
	KOF_SCAN_LNK_NAME      = 1u << 4,  /* NAME_STRING, the description */
	KOF_SCAN_LNK_RELPATH   = 1u << 5,  /* RELATIVE_PATH */
	KOF_SCAN_LNK_WORKDIR   = 1u << 6,  /* WORKING_DIR */
	KOF_SCAN_LNK_ARGUMENTS = 1u << 7,  /* COMMAND_LINE_ARGUMENTS */
	KOF_SCAN_LNK_ICON      = 1u << 8,  /* ICON_LOCATION */
	/* The ExtraData blocks that are not one of the three named below. */
	KOF_SCAN_LNK_EXTRA     = 1u << 9,
	KOF_SCAN_LNK_UNCLAIMED = 1u << 10,

	KOF_SCAN_LNK_VOLUMEID  = 1u << 11, /* drive type, serial, label */
	/* LocalBasePath and CommonPathSuffix - the target, in plain text -
	 * plus their unicode variants when the LinkInfo header is long
	 * enough to have them. The two halves concatenate to the full path,
	 * which is why they are one region and not two. */
	KOF_SCAN_LNK_LOCALPATH = 1u << 12,
	KOF_SCAN_LNK_NETPATH   = 1u << 13, /* CommonNetworkRelativeLink */
	KOF_SCAN_LNK_ENVTARGET = 1u << 14, /* EnvironmentVariableDataBlock */
	KOF_SCAN_LNK_ICONENV   = 1u << 15, /* IconEnvironmentDataBlock */
	KOF_SCAN_LNK_TRACKER   = 1u << 16  /* TrackerDataBlock */
};

#define KOF_SCAN_LNK_STRINGS                                                 \
	(KOF_SCAN_LNK_NAME | KOF_SCAN_LNK_RELPATH | KOF_SCAN_LNK_WORKDIR |   \
	 KOF_SCAN_LNK_ARGUMENTS | KOF_SCAN_LNK_ICON)

/* The regions carved out of the LinkInfo and ExtraData extents. */
#define KOF_SCAN_LNK_PARTS                                                   \
	(KOF_SCAN_LNK_LINKINFO | KOF_SCAN_LNK_VOLUMEID |                     \
	 KOF_SCAN_LNK_LOCALPATH | KOF_SCAN_LNK_NETPATH |                     \
	 KOF_SCAN_LNK_EXTRA | KOF_SCAN_LNK_ENVTARGET |                       \
	 KOF_SCAN_LNK_ICONENV | KOF_SCAN_LNK_TRACKER)

#define KOF_SCAN_LNK_CLAIMED                                                 \
	(KOF_SCAN_LNK_HEADER | KOF_SCAN_LNK_IDLIST | KOF_SCAN_LNK_STRINGS |  \
	 KOF_SCAN_LNK_PARTS)

/*
 * LinkFlags, as MS-SHLLINK numbers them. Only the ones that change how the
 * file is READ are named: the rest are behaviour the shell applies and say
 * nothing about where the bytes are. `flags` carries all 32 regardless, so a
 * rule can ask about one this header did not bother to name.
 */
enum {
	KOF_LNK_HAS_IDLIST    = 1u << 0,
	KOF_LNK_HAS_LINKINFO  = 1u << 1,
	KOF_LNK_HAS_NAME      = 1u << 2,
	KOF_LNK_HAS_RELPATH   = 1u << 3,
	KOF_LNK_HAS_WORKDIR   = 1u << 4,
	KOF_LNK_HAS_ARGS      = 1u << 5,
	KOF_LNK_HAS_ICON      = 1u << 6,
	KOF_LNK_IS_UNICODE    = 1u << 7,
	KOF_LNK_FORCE_NO_INFO = 1u << 8,
	KOF_LNK_HAS_EXP_STR   = 1u << 9,
	KOF_LNK_RUN_AS_USER   = 1u << 13,
	KOF_LNK_HAS_EXP_ICON  = 1u << 14
};

/*
 * LinkInfoFlags, which say which of the two halves of LinkInfo are present.
 * Every one of the 39 shortcuts on this machine that had a LinkInfo had
 * exactly VolumeIDAndLocalBasePath set; the network half is what a shortcut to
 * a share has instead.
 */
enum {
	KOF_LNK_INFO_HAS_LOCAL = 1u << 0,
	KOF_LNK_INFO_HAS_NET   = 1u << 1
};

/*
 * ExtraData block signatures, all of them, because a signature that is not on
 * this list is itself worth reporting - see KOF_LNK_ANOM_EXTRA_UNKNOWN.
 * 0xA000000A is not assigned by MS-SHLLINK and is deliberately absent.
 */
#define KOF_LNK_SIG_ENV        0xA0000001u
#define KOF_LNK_SIG_CONSOLE    0xA0000002u
#define KOF_LNK_SIG_TRACKER    0xA0000003u
#define KOF_LNK_SIG_CONSOLE_FE 0xA0000004u
#define KOF_LNK_SIG_SPECIAL    0xA0000005u
#define KOF_LNK_SIG_DARWIN     0xA0000006u
#define KOF_LNK_SIG_ICONENV    0xA0000007u
#define KOF_LNK_SIG_SHIM       0xA0000008u
#define KOF_LNK_SIG_PROPSTORE  0xA0000009u
#define KOF_LNK_SIG_KNOWNFLDR  0xA000000Bu
#define KOF_LNK_SIG_VISTAIDL   0xA000000Cu

/* Which of those the file actually carried, in `blocks`. */
enum {
	KOF_LNK_BLK_ENV        = 1u << 0,
	KOF_LNK_BLK_CONSOLE    = 1u << 1,
	KOF_LNK_BLK_TRACKER    = 1u << 2,
	KOF_LNK_BLK_CONSOLE_FE = 1u << 3,
	KOF_LNK_BLK_SPECIAL    = 1u << 4,
	KOF_LNK_BLK_DARWIN     = 1u << 5,
	KOF_LNK_BLK_ICONENV    = 1u << 6,
	KOF_LNK_BLK_SHIM       = 1u << 7,
	KOF_LNK_BLK_PROPSTORE  = 1u << 8,
	KOF_LNK_BLK_KNOWNFLDR  = 1u << 9,
	KOF_LNK_BLK_VISTAIDL   = 1u << 10,
	KOF_LNK_BLK_UNKNOWN    = 1u << 11
};

/*
 * ANOMALIES: what the STRUCTURE says, never what it means.
 *
 * Every one of these is a statement a reader could check with a hex editor.
 * "The arguments are long" is here because a length is a fact; "the arguments
 * are malicious" is not, and belongs to a rule that can look at them - which
 * is what KOF_SCAN_LNK_ARGUMENTS exists for.
 */
enum {
	KOF_LNK_ANOM_BAD_SIZE      = 1ull << 0,  /* HeaderSize is not 76 */
	KOF_LNK_ANOM_BAD_CLSID     = 1ull << 1,
	KOF_LNK_ANOM_TRUNCATED     = 1ull << 2,  /* shorter than its header */
	KOF_LNK_ANOM_IDLIST_PAST_EOF = 1ull << 3,
	KOF_LNK_ANOM_INFO_PAST_EOF = 1ull << 4,
	KOF_LNK_ANOM_STRING_PAST_EOF = 1ull << 5,
	KOF_LNK_ANOM_EXTRA_PAST_EOF  = 1ull << 6,
	/*
	 * A COMMAND LINE LONGER THAN A COMMAND LINE.
	 *
	 * 260 characters is MAX_PATH, and a shortcut written by the shell for
	 * a program on the machine is normally well under it. An encoded
	 * payload is not: the whole technique is to put the script in the
	 * arguments, and a base64 blob has a floor. The number is a fact about
	 * the file and the threshold is stated here so a reader can disagree
	 * with it.
	 */
	KOF_LNK_ANOM_ARGS_LONG     = 1ull << 7,
	/*
	 * The icon is on another machine. A shortcut whose ICON_LOCATION is a
	 * UNC path makes the shell fetch it to draw the folder - which is an
	 * outbound authenticated connection caused by LOOKING at a directory.
	 * The fact is the path shape; what it is worth is a rule's to say.
	 */
	KOF_LNK_ANOM_ICON_UNC      = 1ull << 8,
	/*
	 * A LinkInfo offset points outside the LinkInfo. Every one of them is
	 * relative to the start of the structure and bounded by its own stated
	 * size, so this is a file that has been edited or built by hand. The
	 * piece it pointed at is dropped; the rest is still decoded.
	 */
	KOF_LNK_ANOM_INFO_BAD_OFF  = 1ull << 9,
	/*
	 * THE OVERLAP BIT, WHICH DID NOT EXIST AND NOW HAS TO.
	 *
	 * One was written when this parser was, and then removed, with the
	 * reasoning recorded here: the walk went strictly forward and every
	 * region began where the previous one ended, so two of them claiming
	 * the same byte was not something a malformed file could arrange - it
	 * would have been a bug in lnk_parse.c, and an anomaly bit is not how
	 * a bug gets reported.
	 *
	 * That reasoning was correct and has expired. LinkInfo's pieces are
	 * found by OFFSET, and the offsets are the file's: a LocalBasePath and
	 * a CommonPathSuffix pointed at the same byte is a thing anyone can
	 * write, and one of the ways a file is made to read differently to two
	 * readers. The later piece is clipped to start where the earlier one
	 * ended - lower offset keeps the bytes, the same rule runlist.h
	 * settles collisions by - and this says it happened.
	 *
	 * The removal is left written down because the bit looked reasonable
	 * beside the others, was removed for a good reason, and came back for
	 * a better one. What changed was the format's own addressing, not the
	 * opinion.
	 */
	KOF_LNK_ANOM_INFO_OVERLAP  = 1ull << 10,
	/* The EnvironmentVariableDataBlock target is a UNC path: the shortcut
	 * runs something off another machine. */
	KOF_LNK_ANOM_ENV_UNC       = 1ull << 11,
	/* The IconEnvironmentDataBlock path is a UNC path - ICON_UNC's blind
	 * spot, and the field a shortcut actually uses when it is built to
	 * make the shell authenticate outward. */
	KOF_LNK_ANOM_ICONENV_UNC   = 1ull << 12,
	/* A block whose signature is none of the eleven MS-SHLLINK assigns. */
	KOF_LNK_ANOM_EXTRA_UNKNOWN = 1ull << 13,
	/* More ExtraData blocks than there is room to record separately. The
	 * richest shortcut in a corpus of 120 had six. */
	KOF_LNK_ANOM_EXTRA_MANY    = 1ull << 14,
	/*
	 * A LinkFlags BIT AND ITS BLOCK DISAGREE.
	 *
	 * HasExpString says the shell should take the target from an
	 * EnvironmentVariableDataBlock, and HasExpIcon says the same about the
	 * icon and IconEnvironmentDataBlock. Each is a claim about a structure
	 * that is either in the file or is not, so the two can be compared -
	 * and on the 120 shortcuts measured off a running Windows machine they
	 * agreed every time, in both directions: 65 with the flag and the
	 * block, 20 with the icon flag and the icon block, 35 with neither,
	 * and nothing in between.
	 *
	 * So a disagreement is not a thing the shell writes. It is what a file
	 * assembled by hand looks like when the flags were copied from one
	 * shortcut and the blocks from another, or when a block was appended
	 * without its flag.
	 *
	 * NOT RAISED ON A FILE THAT RAN OUT OF BYTES, because there the block
	 * is missing for a reason the PAST_EOF bits already give, and saying
	 * it twice would make a truncated file look like a crafted one.
	 */
	KOF_LNK_ANOM_EXP_MISMATCH  = 1ull << 15
};

#define KOF_LNK_ANOM_COUNT 16

/* The threshold behind KOF_LNK_ANOM_ARGS_LONG, in CHARACTERS. */
#define KOF_LNK_ARGS_LONG 260u

/*
 * How many separately-tagged runs the LinkInfo and ExtraData extents are
 * broken into. Twenty-four, against a measured worst case of six blocks plus
 * five LinkInfo pieces; a file that needs more sets EXTRA_MANY and keeps the
 * rest as one run, so the partition holds either way.
 */
#define KOF_LNK_MAX_PARTS 24u

/* One counted string, as a byte range in the file. */
struct kof_lnk_str {
	uint64_t off;    /* the first byte of the string, past its count */
	uint64_t len;    /* in BYTES, so twice the count when unicode */
	uint32_t chars;  /* the count the file declared */
};

/* One run of the LinkInfo or ExtraData extent, and which region owns it. */
struct kof_lnk_part {
	uint64_t off, len;
	uint32_t cls;    /* a KOF_SCAN_LNK_* bit */
};

struct kof_lnk_info {
	uint32_t version;       /* KOF_LNK_INFO_VERSION the parser filled */
	uint32_t valid;         /* header size and CLSID both agreed */

	uint32_t flags;         /* LinkFlags, all 32 as written */
	uint32_t attributes;    /* FileAttributes of the target */
	uint32_t show_command;
	uint32_t icon_index;
	uint32_t hotkey;
	uint32_t target_size;   /* FileSize, as the link remembers it */
	uint64_t created, accessed, written;   /* FILETIME, as written */

	uint64_t idlist_off, idlist_len;
	uint64_t info_off, info_len;
	uint64_t extra_off, extra_len;

	/* In the order the format stores them, which is also the order they
	 * are parsed - see the note at the top. */
	struct kof_lnk_str name, relpath, workdir, args, icon;

	uint32_t n_extra;       /* ExtraData blocks walked */
	uint32_t unicode;       /* the strings are UTF-16LE */

	uint64_t anomalies;

	/* --- appended at KOF_LNK_INFO_VERSION 2 --- */

	uint32_t info_hdr;      /* LinkInfoHeaderSize: 0x1C, or 0x24 and up */
	uint32_t info_flags;    /* KOF_LNK_INFO_HAS_* */
	uint32_t drive_type;    /* DRIVE_FIXED, DRIVE_REMOTE, ... as written */
	uint32_t volume_serial;

	/*
	 * NUL-terminated rather than counted, so `chars` is what was found
	 * before the terminator and `len` excludes it. The ANSI and unicode
	 * variants are separate because a file may carry either, both, or a
	 * disagreeing pair - which is itself worth being able to see.
	 */
	struct kof_lnk_str vol_label;
	struct kof_lnk_str local_path,  local_path_w;
	struct kof_lnk_str path_suffix, path_suffix_w;
	struct kof_lnk_str net_name;      /* the \\host\share of a CNRL */

	struct kof_lnk_str env_target, env_target_w;
	struct kof_lnk_str icon_env,   icon_env_w;
	struct kof_lnk_str machine_id;    /* TrackerDataBlock, NetBIOS name */

	uint32_t blocks;        /* KOF_LNK_BLK_*, which signatures appeared */
	uint32_t n_parts;
	struct kof_lnk_part part[KOF_LNK_MAX_PARTS];
};

#endif /* KOFENG_LNK_H */
