/*
 * kofinspect.h - what the viewer reads out of one object: its format and
 * regions, the dump of an object to disk, where a declared pattern sits and in
 * which region, and the display names the panels share.
 *
 * Nothing here reports on a scan's result. A module's own output is a note and
 * a mark; the engine's one verdict is the generated diagnoses', and the viewer
 * shows that through the diagnose view.
 */

#ifndef KOFENG_KOFINSPECT_H
#define KOFENG_KOFINSPECT_H

#include <stdint.h>
#include "../libkofeng/kofcore/kofcore.h"
#include "../libkofeng/kofeng.h"
#include "../libkofeng/databases/dbloader.h"
#include "../libkofeng/analyzers/parsers/kofformat.h"
#include "../libkoforbit/evt/kofevt.h"
#include "../libkoforbit/evt/kofevtfmt.h"
#include "../libkoforbit/evt/kofevtlog.h"

/* ---- what a format is ------------------------------------------------------
 *
 * Nothing, any more. Everything a consumer needs in order to see an object the
 * way the engine does - how to sniff it, how to parse it, what its regions are
 * called, what its anomaly bits mean - is one struct published by the engine,
 * because the engine is where the formats are. This header used to carry a
 * second table of the same shape; four test files carried a third, fourth and
 * fifth. See analyzers/parsers/kofformat.h.
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
/* The same, for an object whose format the CALLER knows and no sniff can tell
 * - a process record, an AMSI submission. NULL when that parser refuses it. */
const struct kof_parser *kof_inspect_declare(kof_buf, uint8_t format,
					     struct kof_obj_ctx *, void **);

const struct kof_parser *kof_inspect_identify(kof_buf, struct kof_obj_ctx *,
						   void **view_out);

/* Free a view identify or declare handed back - its tables first, for the formats whose
 * view owns any (zip, pdf). `fmt` is what they answered, NULL when there is no view. */
void kof_inspect_free(const struct kof_parser *fmt, void *view);

/* The subtype in the format's own vocabulary - ET_EXEC, DLL - or NULL. A number
 * would be no use: the same value means REL for an ELF and DLL for a PE. */
const char *kof_inspect_subtype_name(uint8_t fmt, uint8_t sub);

/* An ELF program or section header type, by its name - NULL when it has none. */
const char *kof_inspect_ptype_name(uint32_t t);
const char *kof_inspect_shtype_name(uint32_t t);

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
 *         <i>/                     a recovered child: its own directory, named
 *                                  by where the ENGINE put it in the tree, so
 *                                  a grandchild is <i>/<k>/ and a normalised
 *                                  view is <i>.norm/ beside its object's
 *                                  regions. See dump_rel_dir.
 *         <i>/object               the child's bytes, whole
 *         <i>/00.KOF_SCAN_ALL ...  and the same treatment applied to it
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
 * ONE OBJECT OF A SCAN, WRITTEN WHERE THE ENGINE'S TREE SAYS IT BELONGS.
 *
 * The single entry point both front ends use, called from the engine's
 * per-object callback. `root` is kof_dump_dir_for's answer for the FILE;
 * `name` is the engine's name for this object, and its descent is what decides
 * the sub-directory - see dump_rel_dir, which is where that is worked out.
 *
 * Replaces a loop in each tool. See the note beside the definition for what
 * the two of them disagreed about.
 */
int kof_dump_walk(const char *root, const char *name, kof_buf buf,
		  const struct kof_parser *f,
		  const struct kof_obj_ctx *ctx,
		  struct kof_dump_stat *st,
		  char *dir_out, uint32_t dir_cap,
		  char *err, uint32_t err_cap);

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
 * On a marker present in BOTH the block and the file - the name "shellcode"
 * is one, since it is a record's name field and a string table entry - two
 * lookups that differ answer different offsets in different regions about one
 * marker on one object.
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
	uint64_t at;            /* KGENOME_BROKEN when nowhere at all */
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

/*
 * A hex pattern, respaced into pairs.
 *
 * Only when the pattern is nothing but hex digits and spaces. A pattern with
 * structure in it - ??, [4-8], (41|42) - is left exactly as its author wrote
 * it: the digits inside a gap are hex digits too, so pairing them off blindly
 * would turn [4-8] into something else, and an author who has spaced a pattern
 * to show its shape has said something worth keeping.
 */
void kof_hex_respace(const char *in, char *out, size_t cap);

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
/*
 * HOW RANDOM ONE REGION'S BYTES ARE, in eighths of a bit - 0 to 64.
 *
 * Here rather than in each tool because the region has to be RESOLVED first:
 * a region is several ranges scattered through the object, and its entropy is
 * the entropy of all of them together rather than of the largest or the first.
 * Both tools were about to resolve it themselves, and a second walk of the
 * ranges is a second chance to measure a different thing by accident.
 *
 * WHAT IT IS FOR, beside a size. A size says how much of the object a region
 * is; this says what KIND of bytes they are, and it is the cheapest thing that
 * separates the three cases a reader cares about - code sits near 6, padding
 * and text near 1 to 4, and compressed or encrypted data above 7.5. An
 * UNCLAIMED region at 7.9 is a file somebody appended; the same region at 0.0
 * is alignment.
 *
 * NEVER A VERDICT - see kentropy_eighths. Zero when the region is empty or
 * the object has no parse, which reads as "nothing to measure".
 */
uint32_t kof_inspect_region_entropy(const struct kof_obj_ctx *ctx,
				    kof_buf bytes, uint32_t mask);

void kof_inspect_dotnet(const struct kof_obj_ctx *ctx, const void *info,
			const struct kof_inspect_style *,
			kof_inspect_line out, void *user);

void kof_inspect_toolchain(const struct kof_obj_ctx *ctx, const void *info,
			   kof_buf bytes,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user);

/*
 * THE NAMES FOR A SYMBOL RECORD'S NUMBERS.
 *
 * The block itself is read by kofsym.h - kof_sym_count, kof_sym_rec and
 * kof_sym_u64 are inline there, and both tools had hand copies of all three
 * beside their own copy of these names.
 *
 * The names are here rather than in each tool because the two lists had already
 * drifted: one knew GNU_IFUNC and GNU_UNIQ, the other knew the PE
 * import/export origin, and neither knew both, so which names a reader got
 * depended on which tool they opened.
 */
const char *kof_sym_type_name(uint8_t type);
const char *kof_sym_bind_name(uint8_t bind);
const char *kof_sym_vis_name(uint8_t vis);
const char *kof_sym_origin_name(const uint8_t *blk, uint32_t n);

/*
 * WHAT EVERY SIMILARITY BLOCK SCORED ON THE OBJECT JUST SCANNED.
 *
 * REQUIRED FOR WRITING A MUTATION RULE AT ALL, which is why it is here and not a
 * debugging extra. A rule says `kof_mutation_score(blk) >= 50`; the author has no
 * way to choose that fifty, or to know why a rule did not fire, unless the tool
 * can show what the block actually came to. A verdict alone answers "did it" and
 * never "how close was it".
 *
 * Read from the scanner AFTER a scan, not recomputed: the prepass already
 * counted every block for that object, and counting again would be a second
 * implementation of the thing being inspected - which is how a tool ends up
 * agreeing with itself and disagreeing with the engine.
 *
 * `matched` and `n_hash` are shown beside the percentage because the percentage
 * of a small block moves in coarse steps: 7 of 20 is 35% and so is 7 of 20 with
 * one more window, and an author choosing a threshold needs to see which.
 *
 * Returns how many were written, at most max_out. Zero when the database
 * carries no blocks, which is every build with no mutation rules.
 */
struct kof_mutation_view {
	uint32_t    block;       /* index in the engine's table */
	uint32_t    scan_mask;   /* the region the block was taken from */
	uint8_t     norm;        /* enum kgenome_mutation_norm */
	uint8_t     score;       /* 0..100 */
	uint32_t    matched;     /* hashes of it found in this object */
	uint32_t    n_hash;      /* hashes it has */
	const char *rule;        /* the family the declaring module names */
};

uint32_t kof_inspect_mutation(const struct kof_scanner *sc,
			    struct kof_mutation_view *out, uint32_t max_out);

/*
 * THE REGIONS A PRODUCER DECLARED, filtered by mask - the shape resolve_scan
 * returns.
 *
 * A normalised view cannot be asked what its regions are: its headers describe
 * the file before the transform, so parsing it yields a table over bytes that
 * have moved, and the one region that only exists there - the static library,
 * moved to the end under SLIB_CODE and SLIB_DATA - is not in the headers at
 * all. The engine hands the table over instead, and a tool has only to hold it
 * and answer from it.
 *
 * HERE BECAUSE BOTH TOOLS NEED IT AND THE FILTERING IS THE SAME. They hold the
 * table differently - the viewer keeps one per object, the examiner one per
 * callback - so the binding stays with each, and this is the part that was
 * being written twice.
 */
uint32_t kof_declared_regions(const struct kof_scan_region *rgn, uint32_t n_rgn,
			      uint32_t scan_mask, struct kof_range *out,
			      uint32_t max_out);

/*
 * THE CHAIN RENDERER AND ITS LINE STOOD HERE, and they are gone with the
 * chain matcher: it drew a SEQUENCE, and what replaces the chain is a store
 * of nodes and typed edges, which is not a line per step.
 *
 * TWO THINGS ABOUT IT WERE RIGHT and belong to whatever draws the
 * replacement. It lived HERE rather than in the viewer, because turning
 * engine output into something a person reads is not a terminal's business
 * and both tools want it - it was seven hundred lines inside kofviewer.c
 * and the examiner printed its own flat list of the same steps, two
 * spellings of one thing and the flat one wrong. And it carried NO COLOUR
 * AND NO WIDTH: a row's note came back beside its line rather than appended
 * to it, because how a note is set off - dimmed, bracketed, in a column of
 * its own - is the caller's to choose, and an escape sequence baked in here
 * counts against every caller's field width.
 */

#endif /* KOFENG_KOFINSPECT_H */
