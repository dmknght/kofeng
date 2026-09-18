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
 */

#ifndef KOFENG_LNK_H
#define KOFENG_LNK_H

#include <stdint.h>

#include <kofmod/kofsig.h>

#define KOF_LNK_INFO_VERSION 1

/*
 * THE REGIONS, and every string gets its own because a rule wants to say WHICH
 * string it matched in. "cmd.exe in the arguments" and "cmd.exe in the
 * description" are different statements and a single BODY region could make
 * neither.
 */
enum kof_scan_lnk {
	KOF_SCAN_LNK_HEADER    = 1u << 1,  /* the fixed 76 bytes */
	KOF_SCAN_LNK_IDLIST    = 1u << 2,  /* LinkTargetIDList, undecoded */
	KOF_SCAN_LNK_LINKINFO  = 1u << 3,  /* volume id, local path, UNC */
	KOF_SCAN_LNK_NAME      = 1u << 4,  /* NAME_STRING, the description */
	KOF_SCAN_LNK_RELPATH   = 1u << 5,  /* RELATIVE_PATH */
	KOF_SCAN_LNK_WORKDIR   = 1u << 6,  /* WORKING_DIR */
	KOF_SCAN_LNK_ARGUMENTS = 1u << 7,  /* COMMAND_LINE_ARGUMENTS */
	KOF_SCAN_LNK_ICON      = 1u << 8,  /* ICON_LOCATION */
	KOF_SCAN_LNK_EXTRA     = 1u << 9,  /* the ExtraData block chain */
	KOF_SCAN_LNK_UNCLAIMED = 1u << 10
};

#define KOF_SCAN_LNK_STRINGS                                                 \
	(KOF_SCAN_LNK_NAME | KOF_SCAN_LNK_RELPATH | KOF_SCAN_LNK_WORKDIR |   \
	 KOF_SCAN_LNK_ARGUMENTS | KOF_SCAN_LNK_ICON)

#define KOF_SCAN_LNK_CLAIMED                                                 \
	(KOF_SCAN_LNK_HEADER | KOF_SCAN_LNK_IDLIST | KOF_SCAN_LNK_LINKINFO | \
	 KOF_SCAN_LNK_STRINGS | KOF_SCAN_LNK_EXTRA)

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
	KOF_LNK_ANOM_ICON_UNC      = 1ull << 8
	/*
	 * THERE IS NO OVERLAP BIT, and its absence is deliberate.
	 *
	 * One was written and then removed, because this parser cannot produce
	 * the condition: it walks strictly forward and every region begins
	 * where the previous one ended, so two of them claiming the same byte
	 * is not a thing a malformed file can arrange - it would be a bug in
	 * lnk_parse.c, and an anomaly bit is not how a bug gets reported.
	 *
	 * Written down because the bit looked reasonable beside the others and
	 * would look reasonable again. An anomaly nothing can set is a claim
	 * the format makes and never keeps.
	 */
};

#define KOF_LNK_ANOM_COUNT 9

/* The threshold behind KOF_LNK_ANOM_ARGS_LONG, in CHARACTERS. */
#define KOF_LNK_ARGS_LONG 260u

/* One counted string, as a byte range in the file. */
struct kof_lnk_str {
	uint64_t off;    /* the first byte of the string, past its count */
	uint64_t len;    /* in BYTES, so twice the count when unicode */
	uint32_t chars;  /* the count the file declared */
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
};

#endif /* KOFENG_LNK_H */
