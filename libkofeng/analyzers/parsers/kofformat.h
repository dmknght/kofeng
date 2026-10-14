/*
 * WHICH PARSERS EXIST, AND IN WHAT ORDER THEY GET ASKED.
 *
 * One list, because the answer to "what is this object" must not depend on who
 * asked. The scanner and the examine tools both walk it; before this file each
 * kept its own copy, and the copies had already drifted - a parse that failed
 * mid-way made the scanner try the next format and made the viewer give up.
 *
 * What this file does NOT decide is that policy. It hands out the list and the
 * three facts about each entry that everyone needs - which format, how big its
 * view is, how to sniff and how to parse - and each caller keeps its own rules
 * about allocation lifetime and what a failed parse means. Those differ for
 * good reasons: the scanner reuses one view per format across a whole directory
 * walk, the viewer allocates one and frees it with the file.
 *
 * ORDER IS PART OF THE CONTRACT. Sniffs are not mutually exclusive - a self
 * extracting archive is a PE and a ZIP both - so the first row whose sniff
 * accepts wins. Adding a row in the middle changes what such an object is
 * called, so add at the end unless that change is the point.
 */
#ifndef KOFFORMAT_H
#define KOFFORMAT_H

#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofsig.h"

/*
 * One parser, as everything outside the parser needs to see it.
 *
 * The last four fields are the format's own vocabulary - which regions it can
 * name, what it calls them, what its anomaly bits mean. Each format already
 * publishes those next to its parse (kof_elf_region_name and friends); what was
 * missing was anywhere to ask for them WITHOUT naming a format, and every tool
 * and test that wanted to walk all formats grew its own copy of this join.
 * There were five of those copies.
 *
 * `anomalies` is here because the anomaly word sits at a different place in
 * every view struct, so reading it needs the cast that only the engine should
 * be making.
 */
struct kof_parser {
	uint8_t  format;                       /* enum kof_format */
	uint32_t view_size;                    /* bytes to allocate for the view */
	int (*sniff)(kof_buf);
	int (*parse)(kof_buf, void *view, struct kof_obj_ctx *);

	const uint32_t *regions;               /* every region bit, in order */
	uint32_t    n_regions;
	const char *(*region_name)(uint32_t bit);
	const char *(*anomaly_name)(unsigned index);
	uint64_t  (*anomalies)(const void *view);
};

/*
 * SNIFF AND PARSE AS ONE SCAN, for a row whose parse would repeat the sniff's reading.
 *
 * Only the script row has one (kof_parser_keep_of answers NULL for every other format, the
 * way kof_view_ops_of does, so the table above keeps its shape). The host owns
 * KOF_PARSER_KEEP bytes and hands the same buffer to `sniff` (which fills it) and then to
 * `parse` (which reads it), so what the sniff found is not found again. A row without one
 * is called through its sniff and parse.
 */
struct kof_parser_keep {
	int (*sniff)(kof_buf, void *keep);
	int (*parse)(kof_buf, void *view, struct kof_obj_ctx *, const void *keep);
};

#define KOF_PARSER_KEEP 64u

const struct kof_parser_keep *kof_parser_keep_of(uint8_t format);

/*
 * THE VIEWS THAT OWN MEMORY, and what the host needs of one.
 *
 * Zip, PDF, tar, lha, arj, cab, chm, docole, rar and 7z keep tables as long as the file says,
 * so their views are not plain structs to be zeroed and forgotten: something has to give the engine's per-object
 * ledger a say before the tables grow, charge what they hold, and give it back. Three
 * handles, and a format that has no such view has none of them (kof_view_ops_of answers
 * NULL), which is every format but those:
 *
 *   mem      the view's account (struct kof_view_mem, range.h): the host sets `room`
 *            before the parse and reads `held` and `walked` after it.
 *   release  frees the tables and zeroes the account. The host calls it when the object
 *            is done - the end of sx_scan_object - so what is charged is held for one
 *            object and no longer; a tool calls it before it frees the view.
 *   next     the walk behind a module's kof_zip_next / kof_pdf_next: row `*cursor` of the
 *            table, advancing it; and it counts the call, which is how the host knows the
 *            table was read (struct kof_view_mem.walked).
 */
struct kof_view_ops {
	struct kof_view_mem *(*mem)(void *view);
	void (*release)(void *view);
	const void *(*next)(void *view, uint32_t *cursor);
};

/* The handles for a format's view, or NULL when its view owns no memory. */
const struct kof_view_ops *kof_view_ops_of(uint8_t format);

/* How many rows. Public so a caller that keeps a table of its own, one row per
 * format, can check its length against this and fail to build rather than fall
 * quietly behind. */
#define KOF_PARSER_COUNT 21u

/*
 * The list, in sniff order. Sets *n and returns a pointer that stays valid for
 * the life of the process - the table is static const, so a caller may hold it.
 */
const struct kof_parser *kof_parser_list(uint32_t *n);

/* The row for one KOF_FMT_*, or NULL. For a caller that has a format in hand
 * and wants its parser rather than a sniff. */
const struct kof_parser *kof_parser_of(uint8_t format);

/* The anomaly bits of a format's view that mean a table of the parse was full and
 * what is past it was not read; zero for a format whose module says so itself. */
uint64_t kof_parser_cut_bits(const struct kof_parser *p);

/* Non-zero for a format whose parse clears everything it reads: the host skips its own memset. */
int kof_parser_self_clears(const struct kof_parser *p);

/*
 * THE REGION BITS OF A FORMAT THAT "ANYWHERE IN THE OBJECT" DOES NOT COVER,
 * decided by the bit and not by how it is spelled.
 *
 * A header describes the object rather than being part of what it does: its
 * bytes are offsets, sizes and flags that a rebuild rewrites and a compiler
 * changes between two builds of one source, so a block cut from one measures
 * the toolchain. The static library a normalised view carries on its tail is
 * somebody else's code, and what is offered is the author's. The symbol halves
 * are not bytes of the file at all - the host BUILDS those records while parsing
 * - so a block cut from them has no offsets in any file.
 *
 * Asked in two places that must agree: the carve, which must not offer such a
 * block, and the whole-object pass, which must not feed such a region to a block
 * that named no region. A rule may still NAME one of these, and the engine will
 * look there (mutation_prepass): this is what is offered and swept, not what an
 * author may ask for. Zero for a format with nothing to leave out.
 */
uint32_t kof_parser_region_unoffered(const struct kof_parser *p);

/*
 * The region bit a KOF_SCAN_* SPELLING names, for one format.
 *
 * The way back from region_name, and the direction anything reading a rule
 * needs: a source carries the spelling, because a bit is a format's own
 * numbering and means nothing without one.
 *
 * KOF_SCAN_ALL when the format has no such region, and that is deliberate - a
 * block is a run of bytes and the region is only where it sat in the sample it
 * was cut from. Another build puts the same bytes elsewhere; a format that has
 * no such region at all cannot answer the question, and refusing to look would
 * be a rule that goes quiet on exactly the objects it was written to reach.
 * Callers that care what the rule SAYS keep the spelling and ask this only for
 * where to look.
 */
uint32_t kof_region_mask_of(const struct kof_parser *fp, const char *enum_name);

#endif /* KOFFORMAT_H */
