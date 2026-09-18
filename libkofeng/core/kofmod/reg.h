/*
 * reg.h - a registry script: the text form regedit imports and exports.
 *
 * WHY A PARSER FOR A TEXT FILE. A .reg is not code and nothing interprets it
 * as a language, so on the face of it a scanner could search the whole file
 * and be done. The reason not to is the same one that made LNK worth parsing:
 * WHERE a string sits is the difference between a fact and a coincidence.
 *
 *     [HKEY_LOCAL_MACHINE\...\CurrentVersion\Run]
 *     "Updater"="C:\\Users\\Public\\x.exe"
 *
 * The key path is what makes this persistence. A rule searching the whole file
 * for "CurrentVersion\Run" also matches a .reg that merely READS that key, one
 * that documents it in a comment, and any value whose data happens to contain
 * the words. Splitting the key lines from the value data is what lets a rule
 * say "writes to Run" instead of "mentions Run".
 *
 *
 * THE FORMAT, and all of it is line oriented:
 *
 *     Windows Registry Editor Version 5.00     the version line, first
 *     REGEDIT4                                 the same thing, Windows 9x era
 *
 *     ; a comment
 *     [HKEY_LOCAL_MACHINE\Software\X]          a key this file writes
 *     [-HKEY_LOCAL_MACHINE\Software\X]         a key this file DELETES
 *     "Name"="text"                            a value
 *     "Name"=dword:0000002a
 *     "Name"=hex:aa,bb,cc                      binary, continued with a "\"
 *     "Name"=hex(2):...                        REG_EXPAND_SZ
 *     "Name"=-                                 a value this file DELETES
 *     @="text"                                 the key's default value
 *
 * A hex value CONTINUES ACROSS LINES with a trailing backslash, which is the
 * one place the line orientation breaks and the one place a parser that
 * assumed otherwise would cut a payload in half.
 *
 *
 * WHAT IS DELIBERATELY NOT HERE
 *
 * No hex decoding. A hex(2) value is a REG_EXPAND_SZ holding a command line
 * and decoding it would be genuinely useful - but it is an UNPACKER's job,
 * not a parser's: it produces a new object with its own format, and this
 * layer's contract is to say where bytes are, not to make more of them. The
 * hex runs are published as their own region so whoever writes that unpacker
 * has somewhere to start.
 *
 * No key-path interpretation. Whether HKLM\...\Run is persistence and
 * HKCU\...\Explorer\Advanced is preference is a question about Windows, and
 * the answer changes with the Windows. It belongs in a rule, which is a file
 * somebody can edit without rebuilding the engine.
 */

#ifndef KOFENG_REG_H
#define KOFENG_REG_H

#include <stdint.h>

#include <kofmod/kofsig.h>

#define KOF_REG_INFO_VERSION 1

/*
 * THE REGIONS. Keys and values are separate because that separation is the
 * entire reason this is parsed - see the top.
 */
enum kof_scan_reg {
	KOF_SCAN_REG_HEADER    = 1u << 1,  /* the version line */
	KOF_SCAN_REG_KEYS      = 1u << 2,  /* the [HKEY...] lines */
	KOF_SCAN_REG_VALUES    = 1u << 3,  /* "name"=data, the data included */
	KOF_SCAN_REG_HEX       = 1u << 4,  /* hex: and hex(n): runs */
	KOF_SCAN_REG_COMMENT   = 1u << 5,  /* ; lines */
	KOF_SCAN_REG_UNCLAIMED = 1u << 6
};

#define KOF_SCAN_REG_CLAIMED                                                 \
	(KOF_SCAN_REG_HEADER | KOF_SCAN_REG_KEYS | KOF_SCAN_REG_VALUES |     \
	 KOF_SCAN_REG_HEX | KOF_SCAN_REG_COMMENT)

/* The run classes, in the order the region bits above name them. */
enum kof_reg_class {
	KOF_REG_CLS_HEADER = 0,
	KOF_REG_CLS_KEYS,
	KOF_REG_CLS_VALUES,
	KOF_REG_CLS_HEX,
	KOF_REG_CLS_COMMENT,
	KOF_REG_CLS_COUNT
};

#define KOF_REG_MAX_EXTENTS 2048u

enum {
	KOF_REG_ANOM_NO_HEADER   = 1ull << 0,  /* no version line at the top */
	/*
	 * REGEDIT4, the Windows 9x spelling. Still imported by every Windows
	 * since, and still written by tools that want to be portable - so it
	 * is a fact about the file's age rather than a fault in it.
	 */
	KOF_REG_ANOM_OLD_FORMAT  = 1ull << 1,
	/*
	 * THE FILE DELETES SOMETHING - a "[-HKEY..." key or a "=-" value.
	 *
	 * A structural fact and not a verdict. Uninstallers delete keys and so
	 * does everything that disables a security product; which one this is
	 * depends on WHICH key, and that is a rule's question - the key lines
	 * are a region so it can be asked.
	 */
	KOF_REG_ANOM_DELETES     = 1ull << 2,
	/*
	 * A hex run past KOF_REG_HEX_LONG bytes. Registry values hold icons
	 * and security descriptors, so a long one is ordinary; it is here
	 * because a payload has to be somewhere and this is a place it fits.
	 */
	KOF_REG_ANOM_HEX_LONG    = 1ull << 3,
	KOF_REG_ANOM_EXTENTS_FULL = 1ull << 4,
	KOF_REG_ANOM_OVERLAP     = 1ull << 5,
	/*
	 * A LINE THAT IS NEITHER A KEY, A VALUE, A COMMENT NOR BLANK.
	 *
	 * regedit refuses a file it cannot parse, so a .reg with junk in it is
	 * one nothing would have imported - a fragment, a truncation, or a
	 * file that is not really this format. Counted rather than fatal,
	 * because the lines that DID parse are still worth their regions.
	 */
	KOF_REG_ANOM_JUNK_LINE   = 1ull << 6
};

#define KOF_REG_ANOM_COUNT 7

/* The threshold behind KOF_REG_ANOM_HEX_LONG, in bytes of the hex TEXT. */
#define KOF_REG_HEX_LONG 4096u

struct kof_reg_info {
	uint32_t version;       /* KOF_REG_INFO_VERSION the parser filled */
	uint32_t valid;         /* a version line was found and understood */

	uint32_t n_keys;        /* [HKEY...] lines */
	uint32_t n_deletes;     /* of those, and of the values, the deletions */
	uint32_t n_values;
	uint32_t n_hex;         /* values whose data is a hex run */
	uint64_t hex_longest;   /* the longest of them, in bytes of text */

	uint64_t anomalies;
	uint64_t region_bytes[KOF_REG_CLS_COUNT];

	uint32_t n_runs;
	struct {
		uint64_t off;
		uint64_t len;
		uint32_t cls;
		uint32_t _pad;
	} run[KOF_REG_MAX_EXTENTS];
};

#endif /* KOFENG_REG_H */
