/*
 * kofpack.h - the on-disk pack format.
 *
 * A pack is one file holding a set of signature modules: their code, the strings
 * they declare, the names they report, and the preconditions the host filters on.
 * A database is one or more packs. This header defines the bytes only - no code
 * reads or writes them here, so the format can be stated once and the loader and
 * the packer can both be checked against this file rather than against each other.
 *
 *
 * WHY A PACK AND NOT LOOSE FILES
 *
 * Measured on a synthetic population of 4000 modules, warm page cache:
 *
 *     16000 files, 83463 syscalls to load, 47ms per process
 *
 * Nothing about that is I/O; the cache was warm. It is syscall count and parse
 * work, and both are linear in the number of modules, so 40000 modules is roughly
 * half a second before a byte is scanned. For a scanner invoked once that is a
 * nuisance. For an on-access hook invoked per file it is fatal.
 *
 * So the format is built around one idea: THE LAYOUT ON DISK IS THE LAYOUT IN
 * MEMORY. Loading is mmap plus validation - no parsing, no allocation per module,
 * no copying except the code. The cost stops depending on how many modules there
 * are, and a second process pays almost nothing because the pages are already in
 * the page cache and there is nothing to re-parse.
 *
 * That also answers a question that looked like it needed a loader algorithm -
 * how to load only the signatures an object needs. It needs no algorithm. A pack
 * ruled out by its header is a pack whose pages are never faulted in.
 *
 *
 * WHAT THE FORMAT IS NOT
 *
 * Not portable, and deliberately so. A pack contains native code for one machine,
 * so a byte order or a word size that differed from the host would be a fiction:
 * the code could not run either way. Host order, host word size, and a `machine`
 * field so that a pack built elsewhere is refused loudly instead of entered.
 *
 * Not authenticated. The checksum catches a truncated, corrupted or half written
 * pack. It cannot catch a forged one, because whoever can write the pack can write
 * the checksum in it. The boundary is the permissions on the database directory,
 * exactly as it is for the loose files. Authenticity is a signature section added
 * to this layout later, not a property this version claims.
 *
 *
 * PARSE AND LOAD
 *
 * Order matters here: every step below runs before anything it validates is
 * dereferenced, and no step trusts a value a later step has not yet bounded.
 *
 *   1. open, fstat -> the real file length. Everything is bounded against this
 *      number and never against a length the file states about itself.
 *   2. file length >= sizeof(struct kof_pack_hdr), or there is no header to read.
 *   3. magic, version, machine. Refuse on any mismatch.
 *   4. hdr.file_len == the real file length. Catches truncation before any offset
 *      inside is believed.
 *   5. checksum over [KOF_PACK_CRC_FROM, file_len). Integrity of the whole.
 *   6. every section: off + len does not overflow and does not exceed file_len,
 *      and off has the alignment its content requires.
 *   7. every count against its section: n * stride == section length exactly. Not
 *      "<=", because a section longer than its count means the packer and this
 *      header disagree about the stride, and that is not a pack to load.
 *   8. code section copied to an anonymous mapping, then made read+execute.
 *   9. per module, arithmetic only: code_off + code_len within the code section,
 *      and each table slice within its table. This is the one per-module loop at
 *      load, and it is a few compares with no syscall and no allocation - about
 *      four orders cheaper than the twenty syscalls per module it replaces.
 *  10. per string and per name descriptor: off + len within its pool.
 *
 * Steps 9 and 10 are why a loaded pack needs no bounds check afterwards. The scan
 * path is hot and runs per object per module; paying there for what can be settled
 * once at load is the wrong trade.
 *
 *
 * WHAT THE PACKER MUST GUARANTEE
 *
 * The loader's checks above are the specification. A packer that satisfies them
 * produces a loadable pack; anything else is caught. Beyond correctness, the
 * things the packer decides that the loader cannot:
 *
 *   - the pack-level precondition union (see kof_pack_hdr). Wrong values here are
 *     not caught by any check and cost detections, so they are derived from the
 *     modules, never authored.
 *   - grouping. Which modules share a pack is the packer's whole design question,
 *     and it is what makes the union above selective or useless.
 *   - deduplication. Two modules declaring the same literal should share one run
 *     of pool bytes; the descriptors are (offset, length) precisely so they can.
 *
 *
 * CODE IS COPIED, EVERYTHING ELSE IS MAPPED
 *
 * The tables are used straight out of the mapping. The code section is not: a
 * MAP_PRIVATE file mapping may reflect later writes to the file in any page that
 * has not been copied on write yet, which for an executable mapping means the code
 * can change under a running scan. The copy is 444KB at 4000 modules - nothing
 * against removing that - and it is why the code section's alignment below is
 * about the blobs inside it, not about mapping it directly.
 */

#ifndef KOFENG_KOFPACK_H
#define KOFENG_KOFPACK_H

#include <stdint.h>

/* "KOFP", little end first. Byte order is the host's; this only has to differ
 * from whatever else might be handed to the loader by mistake. */
#define KOF_PACK_MAGIC   0x50464f4bu

/*
 * There is no compatibility range: a pack is a build artefact next to the engine
 * that reads it, and a loader that accepts an older layout is a loader carrying two
 * layouts. A pack whose version differs is refused, not converted.
 *
 * Still moving while the format is pre-release. Nothing has shipped, every database in
 * existence is rebuilt from source by `make db`, and a version that moves before
 * anyone can be holding the old one is a number that records edits rather than
 * compatibility. It gets bumped on the first release and on every shape change
 * after that.
 *
 * 4: struct kof_pack_mod grew family_off and maltype, and KOF_SEC_NAME_POOL's
 * contract changed with it - a finding's name descriptor used to hold the whole
 * composed string ("Botnet.Mirai.Generic"); now it holds only the variant, and
 * the family text lives once per module instead of once per finding. A version 3
 * reader would read a version 4 pack's name pool as full names and be
 * technically not wrong, which is exactly the kind of not-wrong that is worse
 * than a refusal - see KOF_TARGET_NAME and finding_str in scan.c for the shape
 * this now matches.
 */
/*
 * 5: struct kof_pack_mod grew unp_kind. A v4 pack has no way to say whether an
 * unpacker is a packer or a container, and the heuristic now scores that - so a
 * stale pack is refused rather than read with the field assumed zero, which
 * would silently classify UPX as an archive.
 *
 * 7: struct kof_pack_mod grew heur_phase and heur_want, for the rule-based
 * heuristic kind - see kofmod/heur.h.
 *
 * 8: it grew heur_predict_off with it. A rule may now name the family it expects
 * an object to turn out to be, which the engine both reports and uses to decide
 * which decoder to try first. Read as zero from a v7 pack it would mean "no
 * prediction", which is not wrong so much as silently less useful - and a pack
 * is a build artefact, so refusing costs a rebuild and nothing else.
 * 9: struct kof_pack_mod grew heur_level. A rule may be gated to a --heur
 *    level, so evidence that costs more than a default scan should spend can
 *    be asked for rather than always paid. Zero means unstated, which reads as
 *    level 1 - so a v8 pack runs exactly as it did.
 */
#define KOF_PACK_VERSION 9u

/*
 * The machine the code in this pack was built for. Not an architecture the pack
 * detects - the one it runs on. KOF_ARCH_* in kofsig.h is about objects under
 * scan and is a different question with the same word in it.
 */
enum kof_pack_machine {
	KOF_PACK_MACH_NONE    = 0,
	KOF_PACK_MACH_X86_64  = 1,
	KOF_PACK_MACH_ARM64   = 2,
	KOF_PACK_MACH_RISCV64 = 3
};

#if defined(__x86_64__)
#define KOF_PACK_MACH_HOST KOF_PACK_MACH_X86_64
#elif defined(__aarch64__)
#define KOF_PACK_MACH_HOST KOF_PACK_MACH_ARM64
#elif defined(__riscv) && __riscv_xlen == 64
#define KOF_PACK_MACH_HOST KOF_PACK_MACH_RISCV64
#else
#define KOF_PACK_MACH_HOST KOF_PACK_MACH_NONE
#endif

/*
 * What the modules in this pack are for.
 *
 * A pack holds one kind, and the reason is dispatch rather than tidiness. The pack
 * is the unit the engine iterates, and these two kinds are entered at different
 * points: a detector runs while an object is being scanned, an unpacker runs after
 * that, when the engine decides whether the object yields children. Mixing them
 * means the scan loop walks records it must then reject, and the unpack decision
 * walks the whole database to find the few records it wants. Separated, neither
 * loop can see the other's records at all.
 *
 * One kind per pack rather than a kind per module, so the invariant is structural:
 * there is no way to write a mixed pack, and the loader can refuse to enter a blob
 * through the wrong ABI - the same principle as a module being unable to claim a
 * format it was not run against.
 *
 * The kind is not declared in a signature source. It is derived from the entry
 * point the module exports, because a declaration can disagree with the code and
 * an exported symbol cannot.
 *
 * KOF_PACK_UNPACK is reserved, not implemented: an unpacker returns a child object
 * rather than a verdict, and that ABI is its own design. Reserving the value now
 * costs four bytes already spent on padding and means no pack ever exists without
 * the field.
 */
enum kof_pack_kind {
	KOF_PACK_DETECT = 0,      /* entry kof_scan; reports findings */
	KOF_PACK_UNPACK = 1,      /* entry kof_unpack; yields child objects */
	/*
	 * entry kof_heur; reports at KOF_LEVEL_HEUR and nothing above it.
	 *
	 * Its own kind rather than a detector with a ceiling, for the reason the
	 * two above are separate: the scan loop walks every detector for every
	 * object, and a heuristic runs at its own two points in the object's
	 * life. Mixed into that loop it would be stepped over and rejected on
	 * every object that is not at the phase it asked for.
	 *
	 * What it may NOT do is what makes it a kind and not a convention: no
	 * family name, no verdict above HEUR, no child objects. The build
	 * refuses all three - see ksigcompiler.sh - because a check that runs
	 * when the module does is a check that has already loaded the code.
	 */
	KOF_PACK_HEUR   = 2
};

/*
 * Sections, indexed by this enum rather than named in a variable table: the set is
 * known at compile time on both sides, and an index makes the loader's validation
 * a loop over a fixed array instead of a search.
 *
 * The split is hot from cold. PRE_* is what the prefilter reads for every module
 * on every object; MODS is read only for a module the prefilter did not rule out.
 * Keeping them apart is the difference between a prefilter pass touching 80KB and
 * one touching 224KB of strided records at 4000 modules.
 */
enum kof_pack_sec_id {
	KOF_SEC_PRE_TARGET = 0,   /* uint32 x n_mods */
	KOF_SEC_PRE_SCAN   = 1,   /* uint32 x n_mods */
	KOF_SEC_PRE_ARCH   = 2,   /* uint32 x n_mods */
	KOF_SEC_PRE_SIZE   = 3,   /* uint64 x n_mods */

	KOF_SEC_MODS       = 4,   /* struct kof_pack_mod  x n_mods  */
	KOF_SEC_STR_DESC   = 5,   /* struct kof_pack_str  x n_str   */
	KOF_SEC_STR_POOL   = 6,   /* bytes                          */
	KOF_SEC_NAME_DESC  = 7,   /* struct kof_pack_name x n_names */
	KOF_SEC_NAME_POOL  = 8,   /* bytes, each name NUL terminated */
	KOF_SEC_RANGE      = 9,   /* uint32 x n_rng                 */
	KOF_SEC_CODE       = 10,  /* the blobs, concatenated        */

	/*
	 * The inverted index. Optional - both sections empty means the engine falls
	 * back to asking each module in turn, which is correct and does not scale.
	 * See the note on scale below.
	 */
	KOF_SEC_IDX_BITMAP = 11,  /* bytes, (1 << idx_bits) / 8     */
	KOF_SEC_IDX_SLOT   = 12,  /* struct kof_pack_idx x n_idx_slots */

	/* Appended rather than slotted in beside the other preconditions: these ids
	 * are indices into the section table, so inserting one would move every
	 * section after it and silently change the meaning of an existing pack. The
	 * version below is what refuses those instead. */
	KOF_SEC_PRE_SUBTYPE = 13, /* uint32 x n_mods */

	KOF_SEC_COUNT      = 14
};

/*
 * Where a section is. Both fields are 64 bit so the format never needs a second
 * version for the day a database outgrows 4GB; the whole table costs 176 bytes.
 */
struct kof_pack_sec {
	uint64_t off;
	uint64_t len;
};

/* Section start alignment. 64 puts each prefilter column on a cache line, which is
 * the only reason any of them is aligned at all. Code is page aligned so that a
 * future zero-copy mapping is a decision and not a re-layout. */
#define KOF_PACK_SEC_ALIGN  64u
#define KOF_PACK_CODE_ALIGN 4096u

/* Each blob inside the code section, so an entry point is never misaligned for
 * the target's calling convention. Same value the loose-file arena uses. */
#define KOF_PACK_BLOB_ALIGN 16u

/*
 * Limits the format imposes, stated here because this is the file both the writer
 * and the reader consult. They were previously one private constant in the loader
 * and one in the loaded-database header, which is two places to change and one
 * chance to change only one of them.
 *
 * A blob is a signature module, not a program; four megabytes of position
 * independent code with no data section is already far past anything a signature
 * has needed. The cap is what lets the loader refuse a file before allocating for
 * it - see read_whole in ksigbuilder.c.
 *
 * A declared literal has to fit a uint16 length by construction; the real limit is
 * lower because a pattern that long is a file, not a string.
 *
 * A compiled hex pattern gets its own, larger cap: it is a header plus two tables
 * plus bytes and masks, so its length is not comparable with a literal's, and
 * checking it against the literal cap would refuse patterns that are perfectly
 * ordinary to write. Its real bounds are the ones in hexprog.h, which the compiler
 * enforces on the parts rather than on the total.
 */
#define KOF_BLOB_MAX_CODE (4u * 1024u * 1024u)
#define KOF_STR_MAX_LEN   512u

/*
 * A detection name, terminator included.
 *
 * One number because there were three: the compiler accepted 511 characters, the
 * packer read the record with a 256 byte line buffer, and the engine stored 192.
 * A name longer than the smallest of those was cut twice on the way through and
 * nothing said so - an author wrote "Family.Variant" and the scanner reported
 * "Family" with the variant gone. The build now refuses what will not fit rather
 * than delivering something else.
 */
#define KOF_NAME_MAX_LEN  192u
/* The hex program cap lives in hexprog.h with the rest of that encoding's bounds;
 * a reader that validates one needs that header anyway. */

/*
 * The header. Fixed size, first thing in the file, and the only structure whose
 * position is known before anything has been validated.
 */
struct kof_pack_hdr {
	uint32_t magic;
	uint32_t version;

	/*
	 * Checksum over [KOF_PACK_CRC_FROM, file_len), so it covers the rest of
	 * the header as well as the body. Integrity, not authenticity - see the
	 * note at the top of this file.
	 */
	uint32_t crc32;

	uint32_t machine;         /* enum kof_pack_machine */

	/* What the file says its own length is, checked against what fstat says.
	 * A truncated pack is caught here, before any offset inside it is used. */
	uint64_t file_len;

	uint32_t n_mods;
	uint32_t n_str;
	uint32_t n_rng;
	uint32_t n_names;

	/*
	 * Preconditions for the pack as a whole: the union of what its modules
	 * declare, so one test can rule out every module in the file.
	 *
	 * This is what makes packs worth grouping. The prefilter measurement on a
	 * real corpus put target as the single most selective condition, and with
	 * a pack per format that test moves up a level and costs one compare for
	 * thousands of modules instead of one per module. A pack ruled out here is
	 * a pack whose pages are never touched.
	 *
	 * Unions and a minimum, never authored: a value that claims more than its
	 * modules do silently stops running them, and no test notices a detection
	 * that did not happen.
	 */
	uint32_t any_target;      /* OR of every module's target_mask */
	uint32_t any_scan;        /* OR of every module's scan_mask   */
	uint32_t any_arch;        /* OR of every module's arch_mask; 0 -> any */

	/* enum kof_pack_kind. Above the preconditions rather than beside them: a
	 * pack of the wrong kind is not filtered out, it is never looked at by
	 * that part of the pipeline in the first place. */
	uint32_t kind;
	uint64_t min_size_min;    /* smallest size_min in the pack; 0 -> no minimum */

	/* Total memo slots the pack needs, summed over its modules. The engine
	 * turns this into each pack's base when several are loaded; the file
	 * stores only what is true about itself, so it stays immutable and
	 * shareable between processes. */
	uint32_t memo_slots;

	/*
	 * The inverted index, or zeroes if this pack has none.
	 *
	 * idx_bits sizes the bitmap: (1 << idx_bits) bits. Chosen by the packer by
	 * measurement, not by this header, which is why it is a field and not a
	 * constant - the right value depends on how many distinct grams the pack's
	 * patterns actually have, and that is a property of a signature set.
	 *
	 * n_idx_slots is the open-addressed slot table, a power of two.
	 */
	uint32_t idx_bits;
	uint32_t n_idx_slots;

	/*
	 * The module ABI the blobs in this pack were compiled against.
	 *
	 * Not the same as `version` above, and the difference is the whole reason
	 * this field exists. `version` says how this FILE is laid out - where the
	 * sections are, how the records are shaped - and a reader that gets it wrong
	 * reads the wrong bytes. This says which struct kof_content the code inside
	 * expects, and a reader that gets THAT wrong calls a function pointer that is
	 * not there.
	 *
	 * The vtable is append only, so an old module in a new host is safe by
	 * construction: every slot it knows is still where it was. The other
	 * direction is not. A module built against a newer header calls a slot past
	 * the end of the host's table, which is a wild call out of a file - the one
	 * failure this whole design exists to make impossible, since the blob is
	 * untrusted code that runs native.
	 *
	 * kofsig.h has always promised that the host refuses this. It did not: the
	 * constant was defined and read by nothing, and the pack had nowhere to carry
	 * it. Zero means a pack written before the field existed, which can only have
	 * been ABI 1 because there has never been another.
	 */
	uint32_t abi_version;

	struct kof_pack_sec sec[KOF_SEC_COUNT];
};

/* The checksum covers everything after itself. */
#define KOF_PACK_CRC_FROM ((uint64_t)(sizeof(uint32_t) * 3))

/*
 * One module, cold side: read only once the prefilter has decided to run it.
 *
 * Slices, not arrays. The loose-file loader learned this the expensive way: 64
 * inline name slots of 196 bytes cost 12.5KB per module whether or not the module
 * had two names, which at scale was the dominant memory term.
 *
 * memo_base is absent on purpose. It depends on which other packs are loaded
 * beside this one, so it is engine state, not a fact about the file.
 *
 * family_off and maltype are what KOF_TARGET_NAME declares, read here rather
 * than composed into every finding's text. KOF_TARGET_NAME is one declaration
 * per source file, and a module with several KOF_SCAN_INFECT/SUSPECT calls used
 * to pay for that declaration again in every one of them - "Botnet.Mirai." typed
 * into the name pool once per finding instead of once per module, because
 * nothing kept the module-scoped fact apart from the per-finding one. Storing it
 * here instead is the same move struct kof_pack_str's off/len already made for a
 * literal: a fact shared by many records lives once, and what varies per record
 * is what the record actually holds.
 *
 * family_off points into KOF_SEC_NAME_POOL, same pool a name descriptor's off
 * does - a module's family and its findings' variants are both short, both
 * author-chosen text, and interning them together is what lets "Mirai" declared
 * by two different modules share bytes. NUL terminated, unlike a string
 * literal's pool entry, for the same reason a name is: this is printed, not
 * searched. maltype is enum kof_maltype (kofsig.h); the word a reader sees comes
 * from kof_maltype_name, not from anything stored as text.
 *
 * Both are meaningless for an unpack-kind module - KOF_TARGET_NAME is not
 * required there and an unpacker reports nothing by name - but never invalid:
 * the packer interns an empty family for a module that declared none, so
 * family_off is always a real offset to a real (possibly empty) string, and
 * there is nothing here for the loader to reject. Nothing ever calls
 * kof_maltype_name or reads the family pool for such a module; see the note on
 * KOF_TARGET_NAME in kofsig.h for why the declaration is optional there.
 */
struct kof_pack_mod {
	uint32_t code_off;        /* from the start of KOF_SEC_CODE */
	uint32_t code_len;

	uint32_t str_first,  n_str;
	uint32_t rng_first,  n_rng;
	uint32_t name_first, n_names;

	uint32_t family_off;      /* into KOF_SEC_NAME_POOL, NUL terminated */
	uint32_t maltype;         /* enum kof_maltype */

	/*
	 * KOF_UNP_CONTAINER or KOF_UNP_PACKER, for an unpack-kind module.
	 *
	 * Zero and unread on a detector, the same way family_off and maltype are
	 * zero and unread on an unpacker. Carried per MODULE rather than per pack
	 * because a pack groups by preconditions and two unpackers for one format
	 * can be different kinds - unpack-elf holds UPX and Ezuri today, and both
	 * happen to be packers only by accident of what has been written.
	 */
	uint32_t unp_kind;

	/*
	 * WHEN a heuristic rule runs, and WHAT it asks the engine for.
	 *
	 * Their own fields rather than a second meaning for unp_kind and
	 * maltype, which are the two that happen to be spare on a heur module.
	 * Overloading them would work and would be a trap: the day something
	 * prints a module's maltype for diagnostics, a rule's want-mask reads
	 * back as a malware type.
	 *
	 * heur_phase is enum kof_heur_phase_id and is a PREFILTER field - the
	 * scan asks for one phase at a time and must not enter a rule that
	 * declared the other. heur_want is a mask of enum kof_eng_want, fixed at
	 * build time so that what a rule can ask for is a property of the source
	 * and not of the object it is looking at.
	 *
	 * Zero and unread on a detector and on an unpacker.
	 */
	uint32_t heur_phase;
	uint32_t heur_want;

	/*
	 * The lowest --heur level at which the rule runs; 0 means unstated and
	 * is read as 1, so a pack written before this field existed behaves as
	 * it always did. A PREFILTER field like heur_phase - the scan knows its
	 * own level and must not enter a rule that asked for more.
	 */
	uint32_t heur_level;

	/*
	 * The family a rule PREDICTS, into KOF_SEC_NAME_POOL like family_off, or
	 * zero when it predicts nothing.
	 *
	 * Its own field and not family_off, because on a rule that slot already
	 * holds the shape word - "Shellcode" - and the two are different claims.
	 * See KOF_HEUR_PREDICT in kofmod/heur.h.
	 */
	uint32_t heur_predict_off;

	/*
	 * THE SOURCE THIS MODULE WAS WRITTEN IN, relative to the bases tree.
	 *
	 * Into KOF_SEC_NAME_POOL like the family, and zero when the source was
	 * outside the tree.
	 *
	 * Here because the build knew it and used to throw it away, and every
	 * tool that wanted it afterwards had to guess. kofviewer guessed by
	 * scanning the tree and matching a module to a file on the LINE NUMBERS
	 * its detection names sit on - a key that is correct exactly until the
	 * sources are edited, which is the moment somebody rebuilds and looks
	 * again. Rebuilding therefore made the viewer show every rule as one
	 * find_all, because no source matched and it fell back to the database,
	 * which keeps a module's strings and not its logic.
	 *
	 * A fact the build has should be carried, not re-derived.
	 */
	uint32_t src_off;
};

/*
 * What a pool entry holds.
 *
 * The kind is on the descriptor and not in the pool, so the matcher knows which
 * path to take before it reads a byte of content. A literal search is memchr and
 * memcmp; a hex walk is neither, and deciding between them by peeking at the
 * content would mean reading the pool to learn how to read the pool.
 */
enum kof_pack_str_kind {
	KOF_STR_LITERAL = 0,      /* raw bytes; len is the pattern length */
	KOF_STR_HEX     = 1       /* struct kof_hex_hdr and its tables, see hexprog.h */
};

/* Flags for a literal. Both were their own uint8 before; merging them freed the
 * byte the kind needed and left the descriptor at eight. */
#define KOF_STR_ICASE    (1u << 0)
#define KOF_STR_FULLWORD (1u << 1)

/*
 * One declared string: where its bytes are, and how to match them.
 *
 * A pool with (offset, length) rather than an inline buffer. Measured on the
 * generated population, literals average 12.7 bytes against a 512 byte inline
 * slot - 41x. Real signature strings are longer than the synthetic ones so the
 * real factor is smaller, but the shape of the waste is the same, and the pool
 * also lets two modules declaring the same literal share one run of bytes.
 *
 * The bytes are not NUL terminated: a signature literal may contain zero bytes,
 * and a terminator would make the length a second source of truth about where it
 * ends. Length is the only source.
 */
struct kof_pack_str {
	uint32_t off;             /* from the start of KOF_SEC_STR_POOL */
	uint16_t len;             /* bytes at off, whatever the kind */
	uint8_t  kind;            /* enum kof_pack_str_kind */
	uint8_t  flags;           /* KOF_STR_* ; literal only */
	/*
	 * A dense id shared by every module that declared this exact pattern.
	 *
	 * THE DESCRIPTOR IS STILL DUPLICATED, on purpose: a module's strings are a
	 * contiguous slice, and that is what lets the scan path address one without
	 * a lookup. What is not duplicated is the IDENTITY - two modules declaring
	 * the same bytes get the same uid, because the pool already gave them the
	 * same offset and this is that fact written down where the scan path can
	 * use it.
	 *
	 * It is what the memo is keyed by, so a pattern two families happen to
	 * share is searched for once rather than once per family. Nobody can ask a
	 * signature author to know which markers other authors picked, so the
	 * engine has to make the collision free rather than forbidden.
	 *
	 * It is also, exactly, an Aho-Corasick output id: the set of modules that
	 * name one uid is the output list a single automaton state would carry. The
	 * index this engine still needs is built on top of this, not instead of it.
	 */
	uint32_t uid;
};

/*
 * One detection name. Pooled for the same reason as strings: names average 14.5
 * bytes against a 196 byte slot.
 *
 * NUL terminated here, unlike a string literal: this one is text that gets printed
 * and handed to a host as a C string, so the terminator is what it is for.
 */
struct kof_pack_name {
	uint32_t id;              /* the id a module reports */
	uint32_t off;             /* from the start of KOF_SEC_NAME_POOL */
};

/*
 * One entry in the inverted index: a gram, and a string that contains it.
 *
 * Open addressing with linear probing, and duplicates allowed: several strings can
 * share a gram, and they end up in adjacent slots, so a lookup reads forward while
 * the gram matches. No chaining, no pointers - the table is used straight out of
 * the mapping, and a pointer in a file is a relocation waiting to be applied.
 *
 * `str` is an index into KOF_SEC_STR_DESC. KOF_IDX_EMPTY marks a free slot; the
 * marker is on `str` rather than on `gram` because four NUL bytes is a legitimate
 * gram and a signature may well contain it.
 */
struct kof_pack_idx {
	uint32_t gram;
	uint32_t str;
};

#define KOF_IDX_EMPTY 0xffffffffu

/*
 * WHY THE INDEX EXISTS - THE SCALE ARGUMENT, WITH THE MEASUREMENT
 *
 * Measured on 4000 synthetic modules over 400 real objects:
 *
 *     1600000 prefilter evaluations
 *     1292642 modules ran anyway     - the structural preconditions cut 19%
 *     1101242 searches answered from the per-object presence set
 *
 * Per-object scan time was flat from 100 to 4000 modules (1.37 - 1.52 ms), so at
 * this size the database walk is not the bottleneck. The shape of the numbers is
 * what matters: four fifths of the modules are entered for every object, and that
 * term is linear in the size of the database. At a million modules it is roughly
 * 800k module entries and 700k random lookups per object - tens of milliseconds
 * where there is now one and a half.
 *
 * Grouping does not fix this. Splitting packs by precondition is lossless and
 * worth doing, but the measurement says target only removes 18%: the dominant
 * class stays dominant however the files are divided.
 *
 * What fixes it is the direction. Today each module asks the object whether its
 * strings are there, so the number of questions is the size of the database.
 * Inverted, the object's own bytes select the candidates: walk the object once,
 * and for each position ask whether any pattern in the pack starts with these
 * bytes. That question is answered by a bitmap the packer built, so its cost is
 * the size of the object and nothing else.
 *
 * Two levels, because one is not enough:
 *
 *   the bitmap    small enough to stay in L2, and answers "no" for almost every
 *                 position, which is almost every position.
 *   the slots     only touched when the bitmap says maybe. False positives cost
 *                 a lookup and are the price of keeping the first level small.
 *
 * This also removes the 32MB presence table each scanner allocates today, and the
 * per-object pass that fills it: the equivalent table now lives in the pack, is
 * built once by the packer, is read-only, and is shared by every process that maps
 * the pack rather than rebuilt per thread.
 *
 * Which gram to index for each pattern is the packer's decision and cannot be made
 * anywhere else: the useful choice is the rarest gram in the pattern, and rarity
 * is a property of the whole set. That single global decision is most of what
 * separates a good index from a useless one.
 */

/*
 * The layout is the format, so it is asserted rather than described.
 *
 * Every struct above is sized exactly by its fields with no implicit padding, and
 * that is a property a later edit can break without any warning: insert a uint64
 * after a uint32 and the compiler inserts four bytes that no packer writes and no
 * reader expects. A pack written by one build and read by another would then
 * disagree about where everything is, and the first symptom would be a module
 * entered at the wrong offset. These fail the build instead.
 */
_Static_assert(sizeof(struct kof_pack_sec)  == 16,  "pack section entry grew padding");
/* 60 through v8; 64 from v9, which added heur_level. The number moves only
 * with KOF_PACK_VERSION - if it moves without one, the edit is the bug. */
_Static_assert(sizeof(struct kof_pack_mod)  == 64,  "pack module record grew padding");
_Static_assert(sizeof(struct kof_pack_str)  == 12,  "pack string descriptor grew padding");
_Static_assert(sizeof(struct kof_pack_name) == 8,   "pack name descriptor grew padding");
_Static_assert(sizeof(struct kof_pack_idx)  == 8,   "pack index slot grew padding");
/* The fixed fields plus one entry per section. Written that way rather than as one
 * number so that adding a section is a change in one place: the literal caught
 * padding, which is what it is for, but it also failed every time the section table
 * legitimately grew, which taught whoever hit it to update the number rather than to
 * ask why it moved. */
_Static_assert(sizeof(struct kof_pack_hdr) ==
	       80 + KOF_SEC_COUNT * sizeof(struct kof_pack_sec),
	       "pack header changed size");

/* The checksum has to start after itself and cover everything else. */
_Static_assert(KOF_PACK_CRC_FROM == 12, "checksum no longer starts after the crc field");

#endif /* KOFENG_KOFPACK_H */