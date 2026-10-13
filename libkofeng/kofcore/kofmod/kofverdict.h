/*
 * kofverdict.h - what a finding is called: the engine that answered, the
 * verdict, and the malware type, each from one list.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFVERDICT_H
#define KOFENG_KOFVERDICT_H

#include <stdint.h>
#include "kofobjfmt.h"

/*
 * What kind of malware a detection is, for the report string the host composes at
 * report time - see KOF_TARGET_NAME below for the declaration, and
 * kof_maltype_name just after this enum for the word a finding shows.
 *
 * Plain values, not a mask: a module names one type, never an OR of several, so
 * there is nothing here for a bit to buy. Unlike KOF_FMT_* and KOF_ARCH_*, whose
 * numbers are fixed because they are ORed into a mask stored in every pack, these are never
 * combined and never stored as a mask - so a new value is appended at the end and
 * costs nothing to add. Append only, though: an existing entry moving to a different
 * number would be silent everywhere a database built before the move is still read
 * against a build after it.
 */
/*
 * X(NAME, display word). Read like KOF_ARCH_LIST above: the enum, the word a
 * finding shows, and the parse a build tool needs to turn "KOF_MALTYPE_TROJAN"
 * in a source back into a value all come from here. ksigbuilder kept the parse
 * direction as a table of its own, with a comment admitting it was a second
 * copy that could only fail loudly once someone hit it.
 */
/*
 * WHICH PART OF THE ENGINE ANSWERED.
 *
 * A verdict says what a file is; this says what looked. They are different
 * questions and they were the same word for a long time - a finding carried
 * "Heur" where its type goes, which told a reader the answer came from a
 * rule and left no room to say what the file actually was.
 *
 * ANALYZER is the parse and what is read off it - a section that is writable
 * and executable, a segment past the end of the file. The three matchers are
 * named for themselves. A finding carries exactly one: whichever reached it.
 *
 * One list, so the word a verdict prints and the value the engine stores
 * cannot drift - the reason every other enum here is written this way.
 *
 * DIAGNOSE is a value of its own, because a rule whose finding came from the node
 * graph rather than from bytes is a different claim from Pattern and has to read
 * as one - the bytes of a shikata build are new every time and the rule never
 * looked at them.
 *
 * A shape-similarity value, "Overlord", stood between Mutation and Diagnose until
 * the matcher behind it was removed: it identified nothing on its own. The values
 * after it moved up one, so a verdict stored by an older build does not read back
 * as itself.
 */
#define KOF_ENGINE_LIST(X)                                                   \
	X(KOF_ENGINE_NONE,     "None")                                       \
	X(KOF_ENGINE_ANALYZER, "Analyzer")  /* the parse and its anomalies */\
	X(KOF_ENGINE_PATTERN,  "Pattern")   /* declared bytes and strings   */\
	X(KOF_ENGINE_MUTATION,   "Mutation")    /* block similarity             */\
	X(KOF_ENGINE_DIAGNOSE, "Diagnose")  /* what the code does, as a graph */\
	X(KOF_ENGINE_UNPACKER, "Unpacker")  /* a module that opens containers */ \
	X(KOF_ENGINE_SYNDROME, "Syndrome")  /* what the diseases make, inferred */

enum kof_engine_id {
#define KOF_ENGINE_X_ENUM(name, word) name,
	KOF_ENGINE_LIST(KOF_ENGINE_X_ENUM)
#undef KOF_ENGINE_X_ENUM
	KOF_ENGINE_COUNT
};

/*
 * The old name of KOF_ENGINE_DIAGNOSE, same value. Kept so a source that
 * spells it the old way - kofexamine does - still compiles; new text says
 * DIAGNOSE.
 */
#define KOF_ENGINE_PATHOGEN KOF_ENGINE_DIAGNOSE

static inline const char *kof_engine_name(uint32_t v)
{
#define KOF_ENGINE_X_NAME(name, word) if (v == (uint32_t)(name)) return word;
	KOF_ENGINE_LIST(KOF_ENGINE_X_NAME)
#undef KOF_ENGINE_X_NAME
	return "none";
}

/*
 * HOW SURE THE ENGINE IS, which is a different axis from what it found and
 * from what looked. It is the first field of a verdict name for that reason:
 * a reader scanning a log sorts by it before anything else.
 */
#define KOF_VERDICT_LIST(X)                                                  \
	X(KOF_VERDICT_CLEAN,     "Clean")                                    \
	X(KOF_VERDICT_HEUR,      "Heur")                                     \
	X(KOF_VERDICT_SUSPECTED, "Suspected")                                \
	X(KOF_VERDICT_INFECTED,  "Infected")

enum kof_verdict_id {
#define KOF_VERDICT_X_ENUM(name, word) name,
	KOF_VERDICT_LIST(KOF_VERDICT_X_ENUM)
#undef KOF_VERDICT_X_ENUM
	KOF_VERDICT_COUNT
};

static inline const char *kof_verdict_word(uint32_t v)
{
#define KOF_VERDICT_X_NAME(name, word) if (v == (uint32_t)(name)) return word;
	KOF_VERDICT_LIST(KOF_VERDICT_X_NAME)
#undef KOF_VERDICT_X_NAME
	return "clean";
}

#define KOF_MALTYPE_LIST(X)                                                  \
	X(KOF_MALTYPE_VIRUS,    "Virus")                                     \
	X(KOF_MALTYPE_TROJAN,   "Trojan")    /* covers spyware */            \
	X(KOF_MALTYPE_ROOTKIT,  "Rootkit")                                   \
	X(KOF_MALTYPE_BOTNET,   "Botnet")                                    \
	X(KOF_MALTYPE_RANSOM,   "Ransom")                                    \
	X(KOF_MALTYPE_MINER,    "Miner")                                     \
	X(KOF_MALTYPE_ADWARE,   "Adware")                                    \
	X(KOF_MALTYPE_EXPLOIT,  "Exploit")                                   \
	X(KOF_MALTYPE_DROPPER,  "Dropper")   /* covers downloader */         \
	X(KOF_MALTYPE_HACKTOOL, "Hacktool")                                  \
	/*                                                                   \
	 * A WRAPPER THAT WAS RECOGNISED, not malware: an unpacker that names \
	 * a packer it cannot open reports under this word, so the finding    \
	 * reads `Packer:MidgetPack` and no one mistakes it for a family.     \
	 */                                                                  \
	X(KOF_MALTYPE_PACKER,   "Packer")                                    \
	/*
	 * NOT A KIND OF MALWARE, which is why it is last and why no
	 * signature should ever declare it: it is what the ANOMALY model
	 * reports, and that model says a file's structure is odd, not that
	 * the file does anything. It sits in this list because a verdict
	 * needs a word where a type goes and "odd structure" is the honest
	 * one - see kof_verdict_name.
	 */                                                                  \
	X(KOF_MALTYPE_ANOMALY,  "Anomalies")

enum kof_maltype {
#define KOF_MALTYPE_X_ENUM(name, word) name,
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_ENUM)
#undef KOF_MALTYPE_X_ENUM
	/* A terminator, not a bound anything indexes: every table of these is
	 * expanded from the list above, so none can disagree with it, and
	 * kof_maltype_name answers a value from outside with "Malware". */
	KOF_MALTYPE_COUNT
};

/*
 * The word a finding shows for one of the values above. Read at report time: the
 * pack stores the enum value and the family text once per module, not composed
 * into a string until a finding actually needs printing - see
 * struct kof_pack_mod in dbcore.h and finding_str in scan.c.
 */
static inline const char *kof_maltype_name(uint32_t maltype)
{
	switch (maltype) {
#define KOF_MALTYPE_X_NAME(name, word) case name: return word;
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_NAME)
#undef KOF_MALTYPE_X_NAME
	default: return "Malware";
	}
}

/*
 * The identifier a signature source writes for one of these - for a tool that
 * generates source, so the spelling comes from the list above rather than from
 * a second copy of it. kof_maltype_name gives the word a report shows.
 */
static inline const char *kof_maltype_ident(uint32_t maltype)
{
	switch (maltype) {
#define KOF_MALTYPE_X_IDENT(name, word) case name: return #name;
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_IDENT)
#undef KOF_MALTYPE_X_IDENT
	default: return "KOF_MALTYPE_VIRUS";
	}
}

/* The way back: the identifier a signature source writes, to its value. Whole
 * names only, for the reason kof_arch_from_name gives. */
static inline int kof_maltype_from_name(const char *s, int *out)
{
#define KOF_MALTYPE_X_FROM(name, word)                                       \
	if (kof_streq_(s, #name)) { *out = (int)(name); return 1; }
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_FROM)
#undef KOF_MALTYPE_X_FROM
	return 0;
}

/* Case-insensitive, ASCII only - this reads identifiers and file names. */
static inline int kof_strieq_(const char *a, const char *b)
{
	for (; *a && *b; a++, b++) {
		int x = *a, y = *b;

		if (x >= 'A' && x <= 'Z') x += 32;
		if (y >= 'A' && y <= 'Z') y += 32;
		if (x != y)
			return 0;
	}
	return *a == *b;
}

/*
 * THE SAME ENUM FROM ITS DISPLAY WORD - "virus", "Trojan", "MINER".
 *
 * The sibling above reads the IDENTIFIER, which is what a signature source
 * writes. This reads the WORD, which is what a file NAME carries: a
 * signature is stored as <type>_<family>_<nn>.c, and the build derives the
 * target from that rather than making the author write it twice in two
 * spellings that can disagree.
 *
 * Over the same list, so adding a type adds it to both and to the name a
 * finding prints, which is the whole reason KOF_MALTYPE_LIST exists.
 */
static inline int kof_maltype_from_word(const char *s, int *out)
{
#define KOF_MALTYPE_X_WORD(name, word)                                       \
	if (kof_strieq_(s, word)) { *out = (int)(name); return 1; }
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_WORD)
#undef KOF_MALTYPE_X_WORD
	return 0;
}

#endif /* KOFENG_KOFVERDICT_H */
