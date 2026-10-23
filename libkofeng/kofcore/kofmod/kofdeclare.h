/*
 * kofdeclare.h - what a module declares for the build to read: targets, names,
 * strings, patterns and blocks, and the caps on them.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFDECLARE_H
#define KOFENG_KOFDECLARE_H

#include <stdint.h>
#include "kofregion.h"

/*
 * Declare which object formats this module applies to.
 *
 *     KOF_TARGET_FORMAT(KOF_FMT_ELF);
 *
 * Expands to nothing; the build reads it out of the source and the host will not
 * invoke a module for an object outside its target. That is what lets a module skip
 * checking the magic itself.
 *
 * Separate from including a format header: those answer different questions - what
 * the module applies to, and whether it reads that format's parsed facts. More than
 * one format may be named only when no format header is included, because kof_elf()
 * casts ctx->file_header and a module that never casts has nothing to get wrong.
 */
#define KOF_TARGET_FORMAT(mask)

/*
 * Declare that this module targets a kind of EVENT rather than a file format.
 *
 *     KOF_TARGET_EVENT(KOF_EVT_AMSI);
 *
 * The same declaration as KOF_TARGET_FORMAT and read the same way - there is
 * one target axis and this is a second spelling of it, not a second axis. It
 * exists because an author writing a rule about a script submission should not
 * have to call it a format; see KOF_EVT_AMSI.
 *
 * A module may use one or the other and not both: they say the same thing, so
 * two of them is two answers to one question.
 */
#define KOF_TARGET_EVENT(mask)

/*
 * Declare what this module is known as: a type from enum kof_maltype, and a family
 * name this module's author picks.
 *
 *     KOF_TARGET_NAME(KOF_MALTYPE_PACKER, "MidgetPack");
 *
 * Expands to nothing, like KOF_TARGET_FORMAT - ksigbuilder reads it out of the
 * source into the module's record (family_off, maltype). Nothing composes it into a
 * report any more: a module names no object, the diseases do. What reads it is the
 * label the tools show for the module, and an unpack module's family, which routes
 * the child it makes to that family's decoder first.
 *
 * The family string is free text for now - no character restrictions enforced yet.
 * That is a gap, not a decision: enforcing ASCII-only, no spaces, no separators is
 * planned but not built.
 */
#define KOF_TARGET_NAME(type, family)

/*
 * Which kinds of that format, as a mask over the format's own subtype values.
 *
 *     KOF_TARGET_FORMAT(KOF_FMT_ELF);
 *     KOF_TARGET_SUBTYPE(KOF_ELF_REL);        - relocatable objects only
 *
 * Absent means unconstrained, so every module written before this existed keeps
 * running against everything it used to. Expands to nothing, like the other
 * declarations: the build reads it out of the source into the record beside the
 * blob, and the host evaluates it against a fact the collector already produced.
 *
 * The values come from the format header the module includes, and naming one
 * format's values while targeting another is refused at build time - see the note
 * on ctx->subtype for why the numbers overlap.
 */
#define KOF_TARGET_SUBTYPE(mask)

/*
 * Preconditions the host checks without running the module.
 *
 *     KOF_TARGET_SIZE_MIN(1024);
 *     KOF_TARGET_ARCH(KOF_ARCH_X86_64);
 *
 * Both expand to nothing and both work the way KOF_TARGET_FORMAT does: the build reads them
 * out of the source into the record beside the blob, and the host evaluates them
 * against facts the collector already produced. A module that fails one costs a few
 * integer comparisons against that record instead of a call and a scan.
 *
 * Declaring rather than coding the check is what makes it a filter. The same test
 * written inside kof_scan is correct and useless for filtering, because reaching it
 * costs exactly what filtering saves. It follows that a declared precondition must
 * not also be written in the body: two copies of one condition are two things that
 * can disagree, and the declaration is the one the host trusts.
 *
 * Both are optional, and declaring nothing constrains nothing. The default has to
 * fall that way: an unconstrained module runs, so a missing declaration costs time,
 * while a wrongly assumed constraint costs detections silently.
 *
 * A minimum size only, and no maximum, deliberately. A file cannot be smaller than
 * the content it carries, so a lower bound holds however a sample is built; an upper
 * bound is escaped by appending bytes nothing reads, which would turn padding into a
 * way to have the module skipped entirely. A module that wants an upper bound writes
 * it against ctx->obj_size in its own body, where it reads as its own logic rather
 * than as engine level filtering.
 *
 * Only cheap, always-available facts belong here - size, format, architecture.
 * Anything that needs bytes read or a decision made stays in kof_scan, where the full
 * language is available. A precondition language rich enough to express real logic
 * would be a second, worse programming language, which is the trap this whole design
 * exists to avoid.
 */
#define KOF_TARGET_SIZE_MIN(min)
#define KOF_TARGET_ARCH(mask)

/*
 * WHAT KIND OF CONTENT a module takes out - a word, not a format.
 *
 *     KOF_TARGET_FORMAT(KOF_FMT_GZIP);
 *     KOF_TARGET_CONTENT("Deflate");
 *
 * Optional, and for a module that unwraps or carves. The engine names such a
 * module from values it already holds - its step, and the format of the object
 * it ran on - and this adds the one thing neither says: what it took out of it.
 * "Unwrap:Gzip/Deflate", "Unwrap:Raw/Zlib", "Carve:PE/Overlay". A module with
 * nothing to add leaves it out and is named "Unwrap:Tar".
 *
 * A DECLARATION AND NOT A CALL, because it is a property of the module and not of
 * one run of it: a call has to be reached to say anything, and a name a module
 * only gives itself on the path that produces something is a name that is empty
 * on every path that does not.
 */
#define KOF_TARGET_CONTENT(word)

/*
 * How a declared string is compared.
 *
 * Both states are named, including the default, because a call site that spells out
 * "exact" is readable on its own while one that relies on a zero has to be checked
 * against the header. The names are the ones a signature author already knows from
 * other engines rather than the ones the implementation uses internally.
 */
enum kof_str_case {
	KOF_CASE_EXACT = 0,   /* bytes compared as written */
	KOF_CASE_ICASE = 1    /* ASCII A-Z and a-z treated as equal */
};

/*
 * Whether a match has to stand alone.
 *
 * A word byte is [A-Za-z0-9_], the same class other engines use. KOF_WORD_FULLWORD
 * requires that the bytes on both sides of a match are not word bytes, so
 * "/bin/sh" does not match inside "/bin/shX".
 *
 * "Word" is a text notion and an object under scan is not text, so the reason this
 * works at all in a binary is that C strings are NUL separated and NUL is not a
 * word byte. Where that does not hold - a length prefixed string, a packed table -
 * KOF_WORD_FULLWORD will behave in ways that are correct by this definition and
 * surprising in context.
 *
 * The edge of the searched region counts as a boundary. Without that rule the
 * obvious implementation reads the byte before the match, which at offset zero
 * reads outside the object.
 */
enum kof_str_word {
	KOF_WORD_SUBSTRING = 0,  /* match anywhere */
	KOF_WORD_FULLWORD  = 1,  /* neither neighbour is a word byte */
	/*
	 * A WHOLE WHITESPACE-DELIMITED TOKEN - see KOF_STR_TOKEN in dbcore.h.
	 *
	 * FULLWORD asks whether the neighbour is [A-Za-z0-9_], which is right
	 * for an identifier and useless for a marker made of punctuation: "<%"
	 * is a whole tag in classic ASP and a PREFIX of ASP.NET's "<%@", and
	 * "@" is not a word byte, so FULLWORD lets the short one match inside
	 * the long one. This asks the other question - only space, tab,
	 * newline, CR, FF and VT break a run - so "<%" declared this way does
	 * not match "<%@".
	 *
	 * Pick by what the marker is made of, not by which is stricter: a name
	 * wants FULLWORD, a punctuated token wants this.
	 */
	KOF_WORD_TOKEN     = 2
};

/*
 * Name a set of regions.
 *
 *     KOF_TARGET_RANGE(loaded, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);
 *
 * Named so the build can turn it into an index, which is what lets kof_find_str
 * paste both ids from identifiers - it could not do that from an expression like
 * "A | B". A plain #define would work and read as a local implementation detail
 * rather than part of the declared shape of the signature.
 */
#define KOF_TARGET_RANGE(name, scan_mask)

/*
 * Declare a string this module looks for.
 *
 *     KOF_DEFINE_STR(busybox, "/bin/busybox", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
 *
 *     if (kof_find_str(ctx, busybox, loaded)) ...
 *
 * The literal and its comparison options are properties of the string, so they live
 * here. Where to look is not: the same marker can be worth looking for in different
 * places, so the range stays at the call site.
 *
 * Declaring the literal is what moves the search to the host. Three things follow:
 * the options compose instead of multiplying into one macro per combination; the
 * pattern bytes stay out of the blob, so retuning a literal is a data edit and
 * "strings" on a blob reveals nothing; and the host knows every pattern before it
 * runs anything, so it can answer all of them - across every module - in one pass
 * rather than one pass per module. Nothing about a module holding its own pattern
 * bytes can be batched away.
 *
 * At most KOF_MAX_STR_PER_MODULE strings and KOF_MAX_RANGE_PER_MODULE ranges.
 */
#define KOF_DEFINE_STR(name, lit, casing, word)

/*
 * Declare a SIMILARITY BLOCK this module measures against.
 *
 *     KOF_MUTATION_BLOCK(cfg, KOF_SCAN_ELF_CODE, KOF_MUTATION_RAW,
 *                      0x1a2b3c4d, 0x5e6f7a8b, ...);
 *
 *     if (kof_mutation_score(cfg) >= 50)
 *             kof_debug("Family", 0);
 *
 * The hashes are what a researcher's chosen block came to under
 * kof_mutation_mix - see kofmod/kofmutation.h, which also says why the block is a
 * person's choice and not a computation. They are written out by the generator
 * in kofviewer; nobody types them.
 *
 * THE REGION AND THE NORMALIZER ARE PROPERTIES OF THE BLOCK, so they are here
 * rather than at the call site - unlike a string, which is worth looking for in
 * more than one place. A block came from somewhere, hashed a particular way,
 * and asking about it anywhere else is asking a different question.
 *
 * Expands to nothing, like every other declaration here: the build reads it out
 * of the source, assigns the index, and defines the identifier the call site
 * names. A block that was never declared is an undefined identifier at compile
 * time rather than a score that is quietly always zero.
 */
#define KOF_MUTATION_BLOCK(name, scan_mask, norm, ...)

/*
 * The same declaration for a block cut from the STATIC LIBRARY.
 *
 *     KOF_MUTATION_BLOCK_LIB(blk_9f22, KOF_SCAN_ELF_CODE, KOF_MUTATION_RAW,
 *                          0x1a2b3c4d, ...);
 *
 * A separate macro rather than a fourth argument, because the arguments after
 * the normalizer are the hashes - there is nowhere to put a flag that does not
 * move them. It also reads as what it is at the call site, which a trailing
 * enum would not.
 *
 * WHAT IT CHANGES IS WHO MAY SCORE IT. A block declared this way is credited
 * only by windows inside the target's own library spans, and an ordinary block
 * only by windows outside them - see enum kof_mutation_side. The two never add
 * together, which is the whole point: "these samples share a vendored runtime"
 * and "these samples share their author's code" are different claims, and a
 * number that mixed them would be measuring the toolchain.
 *
 * kof_true_find is what names the spans, and it finds none in 86% of stripped
 * static builds - so on those every block is an ordinary one and this macro has
 * nothing to describe.
 */
#define KOF_MUTATION_BLOCK_LIB(name, scan_mask, norm, ...)

/*
 * Declare a string the target holds as UTF-16LE.
 *
 *     KOF_DEFINE_STR_WIDE(iex, "IEX(New-Object", KOF_CASE_EXACT,
 *                         KOF_WORD_SUBSTRING);
 *
 * Written as the text a person reads; stored as the bytes the target has. A
 * PowerShell script block reaches AMSI as UTF-16, so "IEX" is 49 00 45 00 58 00
 * on the wire, and a rule that declared it as a plain literal would look for
 * three bytes that are never adjacent there.
 *
 * A BUILD-TIME EXPANSION, NOT A COMPARE MODE. The high bytes are interleaved
 * here and the result is an ordinary pool entry, so the matcher is unchanged
 * and the presence set still works - the wide form carries its own four
 * concrete bytes to key on. A runtime "wide" flag would have done neither: the
 * fast nocase path anchors inside memchr, and a compare mode that skipped
 * bytes could not use it.
 *
 * ASCII ONLY. Each character becomes one byte and a zero, which is UTF-16LE
 * for U+0000..U+007F and wrong for anything above it. A pattern with a byte
 * over 0x7F is refused rather than encoded incorrectly - a marker that is
 * silently the wrong bytes is a rule that silently never fires.
 *
 * KOF_WORD_FULLWORD WORKS, AND IS TESTED AT CHARACTER GRANULARITY - which is
 * the only way it can mean anything here.
 *
 * A byte-level fullword test asks what the neighbouring BYTES are. After a
 * wide match that is already right: the pattern ends with a zero high half, so
 * the next byte is the low half of the following character. Before it, it is
 * not: the previous byte is the zero high half of the preceding character, and
 * a zero is never a word byte - so the leading test would pass on every match
 * and "IEX" would match inside "PIEXY" while the source said it does not.
 *
 * So a wide literal carries KOF_STR_WIDE and the matcher steps back a whole
 * character on the leading side. See that flag for the exact test.
 */
#define KOF_DEFINE_STR_WIDE(name, lit, casing, word)

/*
 * Declare a byte pattern with wildcards, jumps, alternatives and exclusions.
 *
 *     KOF_DEFINE_HEXSTR(call32,  "E8 ?? ?? ?? ?? 5D C3");
 *     KOF_DEFINE_HEXSTR(nibble,  "E8 ?4 4?");
 *     KOF_DEFINE_HEXSTR(spaced,  "6A 40 [4-6] 8D 4D");
 *     KOF_DEFINE_HEXSTR(anyjmp,  "6A 40 [-] 8D 4D");
 *     KOF_DEFINE_HEXSTR(opcodes, "( E8 | E9 ) ?? ?? ?? ??");
 *     KOF_DEFINE_HEXSTR(notzero, "F4 23 !00 62 B4");
 *     KOF_DEFINE_HEXSTR(notlow,  "F4 23 !?0 62 B4");
 *
 * The syntax is YARA's, because it is the one researchers already write and it
 * covers the cases that come up: "??" and "?4" are masks, "[4-6]" is a gap, a
 * group is a set of alternatives, and "!" excludes. Used with kof_find_str and
 * its _any / _all / _multi forms exactly like a literal - the call site does not
 * know which kind it named, which is the point.
 *
 * A GROUP IS A CHOICE AT THAT POSITION, NOT A GAP. "F4 23 ( 62 B4 | 56 ) 45"
 * matches F42362B445 and F4235645 and nothing else - the alternatives may be of
 * different lengths and may carry wildcards, and what follows the group sits
 * immediately after whichever one matched.
 *
 * "!" IS A BYTE THAT IS ANYTHING BUT THIS. "!00" is any byte except zero and
 * "!?0" any byte whose low nibble is not zero - YARA 4.3 spells it "~" and both
 * characters are accepted. "!??" excludes every byte and is refused.
 *
 * CASE-INSENSITIVE TEXT IS NOT WHAT THIS IS FOR. A word written per character -
 * "(63|43)(6D|4D)(64|44)" for "cmd" - works and costs one part per character,
 * but KOF_DEFINE_STR with KOF_CASE_ICASE says the same thing in one pattern and
 * gives the matcher a whole word to search for. Reach for the hex form when the
 * case fold has to sit inside a pattern that also has wildcards or a jump.
 *
 * Compiled at build time, so a malformed pattern is a build error naming a line
 * rather than a search that silently matches nothing. What the compiler refuses:
 *
 *   a gap inside an alternative      an alternative has to have a length
 *   a leading or trailing gap        that is not a pattern, it is a shorter pattern
 *   no concrete byte anywhere        it would match everything
 *   "!??"                            no byte satisfies it
 *   more parts than the caps allow   see hexprog.h; the bound is what keeps
 *                                    matching a hostile object affordable
 *
 * CASE AND WORD OPTIONS DO APPLY, and are written the way a literal writes them:
 *
 *     KOF_DEFINE_HEXSTR(name, "63 6D 64");                       as written
 *     KOF_DEFINE_HEXSTR(name, "63 6D 64", KOF_CASE_ICASE,
 *                       KOF_WORD_FULLWORD);
 *
 * Both forms are accepted and the short one means what it always meant - bytes
 * as written, matching anywhere.
 *
 * ICASE FOLDS LETTERS AND ONLY LETTERS, and only where the byte is CONCRETE.
 * 0x41 and 0x61 are the same letter; 0x01 and 0x21 differ by the same bit and
 * are not a case pair of anything, so folding by arithmetic would make every
 * pattern with bit 5 set mean twice what it says. A half-masked byte is a
 * nibble and a nibble is not a letter, so "4?" does not fold either, and nor
 * does a negated byte - "anything but this letter" folded would be "anything
 * but either case", which is a broader claim than what was written.
 *
 * FULLWORD AND TOKEN TEST THE NEIGHBOURS OF THE MATCH, which for a hex pattern
 * is not known until the walk has run: a gap or a group makes the span vary, so
 * where the match ENDS is an answer the search produces rather than one it knows
 * in advance. One start can match to several ends and the rule is satisfied by
 * any of them, the same way a literal is satisfied by one occurrence.
 *
 * When they are worth reaching for: a byte pattern that spells text. A marker
 * written as hex because it carries a wildcard in the middle is still a word,
 * and "is it a word on its own" is still the question - it just could not be
 * asked before.
 *
 * One thing worth knowing when writing them: the compiler searches for the longest
 * run of concrete bytes, and the presence set - which rules a pattern out for an
 * object without touching it - keys on four. A pattern whose longest run is shorter
 * than that is searched on every object of its format. The compiler prints the run
 * length for each pattern so this is visible at build time rather than in a profile.
 *
 * A NEGATED BYTE IS NOT A CONCRETE ONE and does not count toward that run: it
 * names every value but one, so there is nothing to search for. Nor is a byte
 * inside a group. A per-character case fold therefore has an anchor of one byte
 * unless something fixed sits beside it - another reason to prefer ICASE on a
 * literal when the whole pattern is a word.
 */
#define KOF_DEFINE_HEXSTR(name, ...)

/*
 * Declare a marker as a REGULAR EXPRESSION.
 *
 *     KOF_DEFINE_REGEX(get, "GET /[a-z]{4}\\.php");
 *     KOF_DEFINE_REGEX(get, "GET /[a-z]{4}\\.php", KOF_CASE_ICASE,
 *                      KOF_WORD_FULLWORD);
 *
 * Used with kof_find_str and its forms exactly like a literal or a hex pattern:
 * the call site does not know which kind it named.
 *
 * IT COMPILES TO THE HEX PROGRAM, which is the whole design. The program is
 * walked as a set of positions that only moves forward, so a match costs what
 * the pattern and the object cost and nothing else - and the constructs that
 * make an ordinary regex engine stoppable by a crafted input are not slow here,
 * they are UNREPRESENTABLE. `*` and `+` are refused because there is nothing to
 * compile them to.
 *
 * It also means a regex inherits, rather than reimplements, the anchor, the
 * presence set, the case and word options and the bounds on how much work one
 * pattern may cause.
 *
 * ACCEPTED:
 *
 *     abc          literal bytes; runs coalesce into one step
 *     .            any byte
 *     [a-z] [^0-9] a class - a 256-bit set, one step
 *     (ab|cd)      alternatives of literal runs, one step
 *     .{4,6}       a gap, the one variable-length thing the program has
 *     X{3}         three copies of X
 *     \. \[ \\ \n \r \t \xNN
 *
 * REFUSED AT BUILD TIME, each naming what to write instead:
 *
 *     * +          unbounded
 *     X?           optional, and an alternative must have a length
 *     [a-z]{2,4}   a variable count of something that is not "any byte"; a gap
 *                  does not know what it skips, so this is refused rather than
 *                  narrowed to {2} or widened to .{2,4}
 *     (a(b|c))     a group inside a group
 *     backreferences, lookaround
 *
 * AND A PATTERN WITH NO CONCRETE RUN IS REFUSED - "[a-z][0-9][a-z]" names no
 * bytes to search for, so the presence set could never rule an object out and
 * it would be walked at every offset of every object of its format. That
 * refusal is the shared back end's, not a rule this declaration applies.
 */
#define KOF_DEFINE_REGEX(name, ...)

/*
 * Caps on what one module may declare.
 *
 * The reason is the host's search memo, which is n_str x n_rng bytes per module: a
 * product, so both factors have to be bounded or one module with many of each costs
 * more than the rest of the database. At 64 each that is 4KB in the worst case and two
 * bytes in the common one.
 *
 */
#define KOF_MAX_STR_PER_MODULE   64
#define KOF_MAX_RANGE_PER_MODULE 64

#endif /* KOFENG_KOFDECLARE_H */
