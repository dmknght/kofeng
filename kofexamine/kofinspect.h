/*
 * kofinspect.h - what the database already knows about one object.
 *
 * A scan answers one question: did any module decide something. This answers the
 * question underneath it - which of the database's markers are in this object at
 * all, whose they are, and for each module that did not fire, WHY it did not.
 *
 * The distinction is the whole point. "Three of Mirai's five markers are here"
 * and "Mirai's markers are all here but Mirai targets ELF and this is a PE" and
 * "the markers are here but not in the region Mirai looks in" are three different
 * findings that a scan collapses into the same silence. The first is a variant to
 * write, the second is nothing, and the third is a build or packing difference -
 * and telling them apart by hand is hours of work that the engine already has the
 * facts for.
 *
 * Nothing here is a verdict and nothing here should be read as one. A module's
 * logic is compiled code in the pack; the most this can say is which of the
 * strings it declared are present. Whether that would have satisfied its
 * conditions is a question only the module can answer, and the answer is the scan.
 */

#ifndef KOFENG_KOFINSPECT_H
#define KOFENG_KOFINSPECT_H

#include <stdint.h>
#include "../libkofeng/core/kofcore.h"
#include "../libkofeng/kofeng.h"
#include "../libkofeng/kofdb/kofdb.h"
#include "../libkofeng/kofparsers/kofformat.h"
#include "../libkoforbit/kofevt/kofevt.h"
#include "../libkoforbit/kofevt/kofevtfmt.h"
#include "../libkoforbit/kofevt/kofevtlog.h"

/* ---- what a format is ------------------------------------------------------
 *
 * Nothing, any more. Everything a consumer needs in order to see an object the
 * way the engine does - how to sniff it, how to parse it, what its regions are
 * called, what its anomaly bits mean - is one struct published by the engine,
 * because the engine is where the formats are. This header used to carry a
 * second table of the same shape; four test files carried a third, fourth and
 * fifth. See kofparsers/kofformat.h.
 *
 * What stays out of that struct is rendering, and on purpose: the two front
 * ends in this tree render nothing alike - one prints lines, one paints panes -
 * and a print callback in the engine would be the printer's shape imposed on
 * both.
 */

/*
 * Identify and parse. Returns the format, fills `ctx`, and hands back a view the
 * caller frees with free(). NULL when nothing claimed the bytes, in which case
 * `ctx` is zeroed and `*view_out` is NULL - and that is a real answer rather
 * than a failure: an object nothing parses still has bytes and still has markers
 * in it.
 *
 * There is no "sniffed but refused" answer to be had here, and that is a
 * property of the parsers rather than an omission: every sniff already
 * establishes what its parse re-checks before giving up. Measured over 2500
 * corpus files and 1080 crafted near-format ones - not one reached a parse that
 * then failed. A parser loosened later would change that, and this is the place
 * the answer would have to come back through.
 */
const struct kof_parser *kof_inspect_identify(kof_buf, struct kof_obj_ctx *,
						   void **view_out);

/* The subtype in the format's own vocabulary - ET_EXEC, DLL - or NULL. A number
 * would be no use: the same value means REL for an ELF and DLL for a PE. */
const char *kof_inspect_subtype_name(uint8_t fmt, uint8_t sub);

/* An ELF program or section header type, by its name - NULL when it has none. */
const char *kof_inspect_ptype_name(uint32_t t);
const char *kof_inspect_shtype_name(uint32_t t);

/*
 * A HEX MARKER IS NOT ITS BYTES.
 *
 * The pack's pool holds a literal's bytes literally, and for a hex pattern it
 * holds a COMPILED PROGRAM instead - a header, a step table, an alternative
 * table and a data area. The two arrive through the same (bytes, len) pair on a
 * touch, and reading a hex one as though it were a literal is wrong twice over:
 * the length is the program's, not the pattern's, and the "bytes" are the
 * program's header. Measured: the ten byte pattern 2F62696E2F7368002D63 reports
 * as 74 bytes of 010001000A000000...
 *
 * These two turn a program back into what a person declared. `span` is the
 * number of object bytes a match covers - one number when the pattern is fixed,
 * a range when a gap varies. `text` renders the pattern: hex digits for concrete
 * bytes, '?' for a masked nibble, '??' per byte of gap, and (a|b) for a choice.
 *
 * Both are bounds checked against `n` because a program in a pack is a file's
 * word about itself. They answer 0 for anything they cannot read.
 */
/*
 * `span` is written as text rather than as numbers because there are three
 * shapes and only one of them is a number. A fixed pattern covers exactly n
 * bytes. A bounded gap covers a range. A pattern with an OPEN gap - [-] or [4-]
 * - has no upper bound at all: the compiler carries KOF_HEX_GAP_OPEN as a
 * sentinel in gap_max, so adding it up yields a number that looks like an answer
 * and is not. Reported as "8+", never as "8-260".
 */
void     kof_inspect_hex_span(const uint8_t *prog, uint32_t n,
			      char *out, uint32_t cap);
uint32_t kof_inspect_hex_text(const uint8_t *prog, uint32_t n,
			      char *out, uint32_t cap);

/* ---- writing an object out -------------------------------------------------
 *
 * What a dump is, and why it is here rather than in the tool that first grew it.
 *
 * A signature is written against a REGION, and a region is not a thing anybody
 * can point at on disk: it is what the parse decided, a set of extents that need
 * not be contiguous and need not be a section. So the way to check what a rule
 * will actually see is to write those extents out and look at them - and the way
 * to check a packed sample is to do the same to what the unpacker recovered,
 * because CODE and DATA of the recovered image are nothing like CODE and DATA of
 * the packed one.
 *
 * Both front ends want it and it must be the SAME dump from both. Two
 * implementations would be two answers to "what is in CODE", and the whole use of
 * the thing is that a directory listing and a signature agree.
 *
 * The layout, unchanged from when only kofexamine wrote it:
 *
 *     _<name>_dump/
 *         00.KOF_SCAN_ALL          the whole object
 *         01.<REGION>              one file per region, in offset order
 *         02.<REGION>
 *         LAYOUT                   every extent of every region, in file order
 *         unpacked.1.<label>       a recovered child, whole
 *         unpacked.1.<label>.regions/   and the same treatment applied to it
 *
 * Nothing here prints. Both callers report differently - one to a terminal, one
 * into a status bar - and a printf in here would be one of them borrowing the
 * other's voice. A failure comes back as 0 with a sentence in `err`.
 */

/* A path plus a dump directory name. An input needing more is refused rather
 * than truncated: a truncated path names a DIFFERENT directory, and creating it
 * would put one object's regions where another object's regions can also land. */
#define KOF_DUMP_PATH_ROOM (4096 + 256)

/*
 * The directory an object's dump belongs in: `_<name>_dump` beside the file.
 *
 * The leading part of the path is kept verbatim - it names a directory that
 * already exists and is not ours to rename - and only the last component is
 * turned into a dump name. A name too long for a filesystem component, or one
 * carrying characters that would make the result awkward to use, keeps its
 * readable prefix and gains a checksum of the whole original, so two files that
 * differ only past the cut still get different directories.
 *
 * 0 when the result would not fit.
 */
int kof_dump_dir_for(const char *path, char *out, uint32_t cap);

/* What one dump wrote, for a caller that wants to say so. */
struct kof_dump_stat {
	uint32_t regions;      /* region files written; an empty region gets none */
	uint64_t region_bytes; /* summed across them */
	uint64_t whole_bytes;  /* the 00.KOF_SCAN_ALL file, counted apart because
				* it is not a region and adding it in would count
				* every byte twice */
};

/*
 * Write one object: the whole of it, each region that has extents, and LAYOUT.
 *
 * Creates `dir`. `f` and `ctx` are what kof_inspect_identify handed back for
 * these bytes; a NULL `f` writes the whole object and nothing else, which is the
 * truthful dump of something no parser claimed.
 *
 * The extents of a region are concatenated in offset order, which is what a
 * module searching that region sees as one logical run of bytes. Two extents that
 * are not adjacent in the file are adjacent in the file written, and that is the
 * honest representation: a pattern spanning the join is one a module would find.
 */
int kof_dump_object(const char *dir, kof_buf buf,
		    const struct kof_parser *f,
		    const struct kof_obj_ctx *ctx,
		    struct kof_dump_stat *st, char *err, uint32_t err_cap);

/*
 * One recovered child, written whole into an existing dump directory, and the
 * directory its own regions go in.
 *
 * `tag` is the caller's name for it - "1.upx", "2" - and becomes
 * unpacked.<tag>. `sub` comes back holding <that>.regions, created and ready to
 * be passed to kof_dump_object; pass NULL for sub_cap 0 to skip making it.
 */
int kof_dump_child(const char *dir, const char *tag,
		   const void *bytes, uint64_t len,
		   char *sub, uint32_t sub_cap, char *err, uint32_t err_cap);

/*
 * Why a module is on the list.
 *
 * Ordered by how much attention it deserves, so sorting by this value is sorting
 * by interest. COMPLETE first because every marker being present is the strongest
 * thing this can observe; INELIGIBLE last because it means the module never ran
 * and its markers being present says nothing about it.
 */
enum kof_touch_kind {
	KOF_TOUCH_COMPLETE = 0,  /* every marker it declares, in the regions it names */
	KOF_TOUCH_PARTIAL,       /* some of them, in the regions it names */
	KOF_TOUCH_ELSEWHERE,     /* present in the object, none in those regions */
	KOF_TOUCH_INELIGIBLE     /* a precondition ruled it out; it never ran */
};

/* One declared marker, and where it turned out to be. */
struct kof_touch_str {
	/*
	 * THE POOL ENTRY, WHICH IS NOT THE PATTERN.
	 *
	 * Named `pool` and not `bytes` on purpose, and renamed after the same
	 * mistake was made three times in two front ends. For a literal these
	 * are the marker's bytes. For a HEX marker they are the COMPILED
	 * PROGRAM - a header, a step table, an alternative table and a data
	 * area - and its length, so reading them as a marker is wrong twice
	 * over: the length is the program's and the "bytes" are its header.
	 * Measured: the three byte pattern 2E2E5C arrives here as 67 bytes.
	 *
	 * Every consumer that wanted "the marker" wanted `text` and `span`
	 * below, which are filled once here so no caller has to know a program
	 * exists. Reach for these two only to walk the program itself.
	 */
	const uint8_t *pool;     /* into the pack's string pool, not owned */
	uint16_t       pool_len;
	uint8_t        kind;     /* enum kof_pack_str_kind */

	/*
	 * The marker as a person wrote it, and how much of the object one match
	 * covers - the two questions every display actually asks.
	 *
	 * `text` is the hex spelling: plain digits for concrete bytes, '?' for
	 * a masked nibble, [N-M] for a gap, (a|b) for a choice. A literal gets
	 * its bytes hex encoded, so one field answers for both kinds.
	 *
	 * `span` is text and not a number because there are three shapes and
	 * only one is a number: a fixed pattern covers exactly n bytes, a
	 * bounded gap a range ("8-12"), and an open gap has no upper bound at
	 * all ("8+") - the compiler carries a sentinel there, and adding it up
	 * yields a number that looks like an answer and is not.
	 */
	char           text[96];
	char           span[16];
	/*
	 * The same span as a number, for the one caller that needs arithmetic
	 * rather than a label: the hex pane, deciding which bytes of the object
	 * belong to this marker.
	 *
	 * The MINIMUM, because a highlight has to commit to a length and the
	 * shortest match is the only one that is always right - a pattern with
	 * an open gap has no longest. Exact whenever the pattern is fixed,
	 * which is nearly always.
	 *
	 * This is the field whose absence caused the bug the rename exists for:
	 * the pane used the pool length, so ZipSlip's three byte 2E2E5C lit up
	 * 67 bytes of the object - the marker plus sixty-four bytes of whatever
	 * followed it.
	 */
	uint32_t       span_min;
	/*
	 * How long the match AT `at` actually is, which is not span_min the
	 * moment a pattern has a gap in it.
	 *
	 * span_min is a property of the PATTERN - the shortest thing it could
	 * match - and it is the right answer when nothing has been found. Once
	 * something has, the highlight should cover what was found: measured on
	 * a Tsunami marker, `474554202F[4-7]2E7473756E616D69` reports a span of
	 * "17-20", and the occurrence in the object is "GET /armv4l.tsunami",
	 * nineteen bytes. Lighting seventeen of them cuts the last two
	 * characters off the thing the reader was shown.
	 *
	 * Equal to span_min whenever the pattern is fixed, which is nearly
	 * always, and KOF_BROKEN's absence is not a case: it is only filled
	 * when `at` was found.
	 */
	uint32_t       span_at;
	uint8_t        flags;    /* KOF_STR_ICASE | KOF_STR_FULLWORD */
	/*
	 * The pattern's identity across the WHOLE database, not within its pack -
	 * pack-local ids plus the pack's base, the same number the engine's memo
	 * is keyed by. Two rows carrying one uid are two modules that picked the
	 * same bytes, which is worth being able to see.
	 */
	uint32_t       uid;

	/*
	 * Two answers, not one, and they are the reason this file exists.
	 *
	 * `at` is where the marker is in the object, searched over everything, so a
	 * viewer can highlight it whether or not it counts for this module. `in_rgn`
	 * is whether it is inside the regions this module actually names, which is
	 * the only one that would have counted. A marker with `at` set and `in_rgn`
	 * clear is the interesting case: present, and in the wrong place.
	 */
	uint64_t       at;       /* KOF_BROKEN when absent from the object */
	/*
	 * WHICH BUFFER `at` IS AN OFFSET INTO.
	 *
	 * Zero for the object's bytes. KOF_SCAN_SYM_IMP or KOF_SCAN_SYM_EXP
	 * when the marker was found in the object's symbol block, which is
	 * built and is not part of the file - so a caller must not hand that
	 * number to anything that expects a file offset.
	 *
	 * Without it, a marker declared over a symbol record was reported
	 * "absent" with region "-" on a row whose own header said 2/2: the
	 * search that fills `at` only ever looked at the file, where the
	 * block's records are not.
	 */
	uint32_t       sym;
	/*
	 * WHICH REGION OR HALF `at` IS IN, as a mask.
	 *
	 * Carried rather than looked up again by each caller: the list used to
	 * re-derive it from `at` while the draft panel read it off the
	 * locator's answer, which is the same fact computed two ways - and the
	 * two ways disagreed for an offset in the symbol block, where a
	 * file-offset lookup has nothing to say.
	 *
	 * A caller turns it into a word with the format's own region names;
	 * that part is presentation and stays with the caller.
	 */
	uint32_t       at_mask;
	int            in_rgn;
};

/* One module, and how close this object came to it. */
struct kof_touch {
	const struct kof_module *mod;
	const char             *family;     /* "" when the module declared none */
	uint32_t                maltype;
	enum kof_touch_kind     kind;

	/*
	 * Did this module actually report something on this object.
	 *
	 * A separate fact from every other one here, and the only one that is a
	 * verdict. Every marker being present is not it: a module's conditions
	 * are compiled code, and "all five markers are here" says nothing about
	 * whether the module asked for all five, asked for two of them, or asked
	 * for something else entirely alongside. Only a scan knows, so it is
	 * the caller's scan result that fills this, handed to kof_touch_object.
	 */
	int                     fired;
	const char             *fired_name;  /* the variant it reported, if any */
	/*
	 * AND HOW STRONGLY, which is not the same question as whether.
	 *
	 * A module that fired may have reported INFECT, SUSPECT or HEUR, and a
	 * pane that paints all three the same colour tells a reader less than
	 * the scanner's one-line output does. KOF_LEVEL_*; only meaningful when
	 * `fired`.
	 */
	uint32_t                fired_level;

	/* Set only for KOF_TOUCH_INELIGIBLE: the precondition that ruled it out,
	 * as the word a reader needs rather than as a mask to decode. */
	const char             *ruled_out;

	/*
	 * The variants this module can report, in declaration order.
	 *
	 * Listed rather than resolved, because which one a module WOULD report is
	 * a property of its logic and its logic is compiled code. What can be said
	 * is which names it holds, and that is worth saying: it is the string a
	 * scanner would print, so a row here can be matched against a verdict by
	 * eye instead of by guessing which family the family name belongs to.
	 */
	uint32_t                n_names;
	const char            **name;       /* n_names of them, owned; entries are not */
	uint32_t               *name_id;    /* the source line each was written on */

	uint32_t                n_str;      /* markers the module declares */
	uint32_t                n_present;  /* found anywhere in the object */
	uint32_t                n_in_rgn;   /* found where the module looks */
	/*
	 * WHERE THE MODULE LOOKS, as the region mask it declared.
	 *
	 * Carried because the database HAS it and the panel was inventing a
	 * substitute: a rule opened from the pack showed its range as "-" and
	 * its matcher as WHOLE-FILE, so a marker declared in SYM_EXP was then
	 * searched over the file, where the block's records are not, and
	 * reported absent. The pack keeps the strings and not the logic - but
	 * the range is not logic, it is a fact about each search.
	 */
	uint32_t                scan_mask;
	/*
	 * THE PRECONDITIONS THE MODULE DECLARED, which the pack also keeps.
	 *
	 * Same reason scan_mask is here: the panel writes these back out when a
	 * rule is regenerated, and it had no way to learn them - so opening a
	 * rule from the database and saving it dropped every KOF_TARGET_ line
	 * it had, silently widening it. size_min is a size; the two masks are
	 * 1u << value, the way the host tests them.
	 *
	 * There is no maximum here because the engine has none by design - see
	 * KOF_TARGET_SIZE_MIN in kofsig.h. A rule wanting an upper bound writes
	 * it in its body, and the panel reads that back from the source.
	 */
	uint64_t                size_min;
	uint32_t                arch_mask;
	uint32_t                subtype_mask;
	struct kof_touch_str   *str;        /* n_str of them, owned */
};

/*
 * Every module the object touches at all, most interesting first.
 *
 * A module none of whose markers are present and which reported nothing is not
 * on the list: it is not evidence, and at database scale it would be the whole
 * list - most of a database has no business with any given object.
 *
 * `ctx` must be the parsed context for `buf` - the regions come from the parse,
 * so a module's declared range cannot be resolved without it. An object nothing
 * identified still works: no format means no region resolves, every marker is
 * ELSEWHERE, and that is the truthful answer rather than an empty one.
 *
 * Returns 0 on allocation failure, in which case nothing is written.
 */
/*
 * `finding` are the names a scan reported for THIS object, as the engine
 * composes them - "ELF-a32/Botnet:Mirai-0i0bq". Passed in rather than applied
 * afterwards because they change which modules belong on the list at all: a
 * module that fired has to be there whether or not it declares a marker, and a
 * structural detection declares none.
 */
/* The matcher, forward declared: the locator below takes two of them and this
 * header does not otherwise need to know what one contains. */
struct kof_match_ctx;

/*
 * ---- WHERE A MARKER IS, AND IN WHICH REGION -----------------------------
 *
 * ONE RULE, because two lists show it and they must not disagree.
 *
 * The status line's marker list and the draft panel's string table exist for
 * different reasons and show different columns, but "where is this marker" and
 * "which region is that" are the same two questions in both - so they are
 * answered here and read there.
 *
 * They used to be answered twice. kof_touch_object took the first occurrence
 * anywhere in the file and worked out `in_rgn` separately; the panel preferred
 * an occurrence the module would actually count and asked the symbol halves
 * before the file. On a marker present in BOTH the block and the file - the
 * name "shellcode" is one, since it is a record's name field and a string
 * table entry - the two answered different offsets in different regions about
 * one marker on one object.
 *
 * THE RULE:
 *   1. the symbol halves the mask names, imports before exports, because that
 *      is the order kof_find_str asks in and therefore the occurrence that
 *      actually decided the detection;
 *   2. otherwise the file, preferring an occurrence inside the mask;
 *   3. otherwise the first occurrence anywhere, with `off_rgn` set to say the
 *      rule cannot fire on it.
 *
 * Hits are collected from ONE space only, so every offset in `hits` is in the
 * same buffer and a caller cannot mix them.
 */

/*
 * The regions of one object, resolved once.
 *
 * Region lookup is per hit and resolving a region walks the segment and section
 * tables, so the answer is prepared once per object rather than recomputed for
 * every marker of every module.
 */
struct kof_region_map {
	uint32_t          mask[32];
	struct kof_range *ext[32];
	uint32_t          n[32];
	uint32_t          n_reg;
};

int      kof_region_map_build(struct kof_region_map *,
			      const struct kof_obj_ctx *,
			      const struct kof_parser *);
void     kof_region_map_free(struct kof_region_map *);
/* The region holding a file offset, as a region mask; 0 when none does. */
uint32_t kof_region_map_at(const struct kof_region_map *, uint64_t off);

#define KOF_LOCATE_HITS 64u

struct kof_locate {
	uint64_t at;            /* KOF_BROKEN when nowhere at all */
	uint32_t at_mask;       /* the region or half holding `at` */
	uint32_t sym;           /* KOF_SCAN_SYM_* when `at` is in the block */
	uint32_t seen_mask;     /* every region the file occurrences are in */
	int      in_rgn;        /* `at` is somewhere the mask names */
	int      off_rgn;       /* present, and nowhere the mask names */
	uint32_t cur_hit;       /* which of `hits` is `at` */
	uint32_t n_hits;
	int      clipped;
	uint64_t hits[KOF_LOCATE_HITS];
	uint32_t hit_len[KOF_LOCATE_HITS];
};

/*
 * `m` is a matcher for the object's bytes and `msym` one for its symbol block;
 * both are begun here. `scratch` is an extent buffer of `cap` entries.
 * Returns whether anything was found.
 */
int kof_locate_str(struct kof_match_ctx *m, struct kof_match_ctx *msym,
		   const struct kof_region_map *map, kof_buf obj,
		   const uint8_t *sym, uint32_t sym_n, uint32_t mask,
		   const uint8_t *pat, uint16_t plen, uint8_t kind,
		   uint8_t flags, uint32_t span_min, uint32_t span_max,
		   struct kof_range *scratch, uint32_t cap,
		   struct kof_locate *out);

/*
 * `span_min`/`span_max` are the PATTERN's span, which for a hex marker is not
 * `plen`: there `pat` is a compiled program and its length is the program's -
 * the three byte pattern 2E2E5C arrives as 67 bytes of it. Passing plen instead
 * made a hit's reported length the program's size, so the pane lit the marker
 * plus whatever followed it.
 */

int  kof_touch_object(struct kof_engine *eng, kof_buf buf,
		      const struct kof_obj_ctx *ctx,
		      const struct kof_parser *fmt,
		      const struct kof_finding *finding, uint32_t n_finding,
		      struct kof_touch **out, uint32_t *n_out);

void kof_touch_free(struct kof_touch *v, uint32_t n);


/* The word for a kind, for a caller that prints one. */
/*
 * A REGION ENUM NAME, AS A COLUMN WANTS TO READ IT.
 *
 * Every region is spelled KOF_SCAN_<FMT>_<NAME> and no reader needs the first
 * three parts: the object's own row has already said which format it is. So
 * this returns what follows them - HEADER, OBJECTS, STREAM_PACKED - and the
 * whole name for anything not shaped that way, because a name this cannot
 * parse is one a reader should see in full rather than trimmed at a guess.
 *
 * HERE RATHER THAN IN EITHER TOOL, because both had their own and they did not
 * agree. kofviewer took everything after the LAST underscore, which is the
 * same answer for HEADER and a wrong one for every region whose name has two
 * words: STREAM_PACKED read as "PACKED" and STREAM_IMAGE as "IMAGE". With one
 * stream region that was terse; with four of them - PLAIN, PACKED, IMAGE,
 * FONT - the rows stopped saying they were streams at all, and "IMAGE" beside
 * a child named "Image" read as though the tree were listing content rather
 * than regions. Reported as the regions having gone missing, which from the
 * outside is exactly what it looked like.
 */
const char *kof_region_label(const char *enum_name);

/*
 * A PDF TEXT STRING, MADE FIT TO PUT ON A LINE.
 *
 * The parse hands back the range INSIDE the delimiters and decodes nothing,
 * which is right - a decoded copy needs somewhere to live and a parser has
 * nowhere. Three things then stand between those bytes and a readable line,
 * and every host that shows one meets all three:
 *
 *   UTF-16, which is how every Word-produced document writes these. A BOM of
 *   FE FF and then two bytes per character - so rendered as bytes it reads
 *   ".M.i.c.r.o.s.o.f.t", which is what the first attempt at this printed.
 *   Only the low half of each pair is kept, because this is one terminal line
 *   and not a text renderer.
 *
 *   ESCAPES, in a literal string: \( is a parenthesis rather than the end of
 *   the value, and a title of "Report \(final\)" printed its own backslashes.
 *
 *   HEX, when the value was written <4A4B>. Told by the flag the parse
 *   records, because the bytes cannot say: "0FACED" is a legal spelling of
 *   three bytes and a legal word, and guessing is a title rendered as
 *   gibberish or the reverse.
 *
 * Non-printable bytes become '.', which is what keeps a terminal escape out
 * of a report - the same rule kof_src_label follows for a child's name.
 *
 * Here, in the shared layer, because kofexamine and kofviewer both show these
 * and a second copy of the three rules is a second thing that renders a title
 * differently.
 *
 * Returns the characters written, and always NUL terminates when cap is
 * non-zero.
 */
uint32_t kof_pdf_text(const uint8_t *p, uint64_t n, int hex,
		      char *out, uint32_t cap);

const char *kof_touch_kind_name(enum kof_touch_kind);

/* ---- describing one collected event ---------------------------------------
 *
 * WHY THIS IS AN API AND NOT A PANEL.
 *
 * Two tools show a record: the viewer's dashboard and kofexamine, and they were
 * about to grow two descriptions of the same thing. That is the mistake the
 * field accessors in kofevtfmt.h were made to prevent one level down - a page
 * and a panel that word the same record differently are two vocabularies for
 * one fact - and it applies again here, to the LAYOUT rather than the wording.
 *
 * So the composition lives here and the callers only supply a sink. Each line
 * arrives finished; what a caller does with it - add it to a scrolling page,
 * put it to stdout - is the only thing that differs between them.
 */

/* Where one finished line goes. */
typedef void (*kof_inspect_line)(void *user, const char *text);

/*
 * The attributes a caller wants in those lines, or NULL for none.
 *
 * Supplied rather than chosen here, because the two tools do not share a
 * palette: the viewer paints from kofview.h, and kofexamine turns colour off
 * whenever its output is not a terminal - its output is piped into grep and
 * diffed against itself, and an escape sequence in either is a bug rather than
 * a preference. NULL gives plain text, which is what that case needs.
 */
/* Named for the library, not for events: the toolchain rows use it too. */
struct kof_inspect_style {
	const char *id;    /* a field's name */
	const char *loc;   /* an offset */
	const char *warn;  /* a flag row - the record is short, or odd */
	const char *off;   /* back to normal */
};

/* The log's own facts: what collected it, and how much is in it. */
void kof_inspect_event_log(const struct kofevt_log_hdr *h,
			   uint64_t events, uint64_t records,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user);

/*
 * One record's fields, TWO TO A LINE.
 *
 * These values are short and a dozen of them down a page is a tall column of
 * mostly empty line. Paired left to right rather than filled down two columns,
 * because a page scrolls: a reader meets the rows in the order they are
 * written, and there is no second column to read back up.
 *
 * A flag row takes the width to itself - it has no offset, its text is a
 * sentence rather than a value, and pairing it with a number would read as two
 * halves of one fact.
 */
void kof_inspect_event(const struct kof_evt *e,
		       const struct kof_inspect_style *st,
		       kof_inspect_line out, void *user);

/*
 * WHAT A SCAN DECIDED ABOUT AN OBJECT.
 *
 * One line per finding: the verdict, the family it named and the module that
 * named it. Nothing is interpreted here - a finding already carries its own
 * name and where each part of it starts, so this is a rendering and not a
 * second opinion.
 *
 * Emits nothing when there are none, which is the common case and is not a
 * result worth a line of its own: whoever calls this decides whether silence
 * needs saying.
 */
void kof_inspect_findings(const struct kof_finding *f, uint32_t n,
			  const struct kof_inspect_style *st,
			  kof_inspect_line out, void *user);

/*
 * HOW MANY OF EACH VERB A LOG HOLDS.
 *
 * `count` is indexed by verb and `keep` is the mask of the ones a caller is
 * showing - a viewer with a filter on wants the hidden ones marked rather than
 * dropped, because a verb that is present and hidden is a different fact from
 * one that is not there. Pass ~0u when nothing is filtered.
 *
 * Two to a line, which is what makes it readable: these are a word and a
 * number, and a dozen of them down a page is a column of mostly empty line.
 */
void kof_inspect_event_verbs(const uint64_t *count, uint32_t keep,
			     const struct kof_inspect_style *st,
			     kof_inspect_line out, void *user);

/*
 * WHAT BUILT AN OBJECT, as far as the object is willing to say.
 *
 * Managed or native, statically or dynamically linked, which compiler left its
 * stamp - the questions asked in the same breath as "what format is this", and
 * answered from the parsed view rather than guessed.
 *
 * Here rather than in a panel for the reason kof_inspect_event is here: two
 * tools show this and they must not word it two ways. `bytes` is the object
 * itself, needed because one of the answers - ELF's .comment - is a section's
 * contents rather than a parsed field.
 *
 * Emits nothing when the format has nothing to say, which is most of them.
 */
/*
 * WHERE THE .NET METADATA IS, one line per heap.
 *
 * A separate call from kof_inspect_toolchain, which answers a different
 * question: that one says WHAT BUILT the image - the runtime version, the
 * metadata version, the linker stamp - and this says WHAT IS IN IT and where.
 * A reader asks the first before they have decided the sample is interesting
 * and the second once they have.
 *
 * The heaps are also the only rows that say anything about a truncated
 * assembly: a submission cut short by its provider has heaps declared past its
 * own end, and a run of zero-length rows is how that looks - which is worth
 * seeing, because it is also the reason a rule for one of them did not fire.
 *
 * Emits nothing for a native image, which is every image that is not managed.
 * `info` is the format's view, as kof_inspect_toolchain takes it.
 */
void kof_inspect_dotnet(const struct kof_obj_ctx *ctx, const void *info,
			const struct kof_inspect_style *,
			kof_inspect_line out, void *user);

void kof_inspect_toolchain(const struct kof_obj_ctx *ctx, const void *info,
			   kof_buf bytes,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user);

#endif /* KOFENG_KOFINSPECT_H */
