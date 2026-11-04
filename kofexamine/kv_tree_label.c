#define _GNU_SOURCE
#include "kv.h"
#include "kv_tree_private.h"

/*
 * WHAT TO CALL A REGION BIT ON THIS OBJECT.
 *
 * Its own parser, normally. An object with a DECLARED table has no parser and
 * its bits are the PARENT's, so the parent's format is what names them - see
 * struct object.rgn_fmt. Without this, region_row dereferenced a null parser
 * the moment a normalised view was drawn.
 */
const struct kof_parser *obj_region_vocab(const struct object *o)
{
	if (o->n_rgn)
		return kof_parser_of(o->rgn_fmt);
	return o->fmt;
}

void region_row(struct view *v, const struct object *o, uint32_t i,
		       uint32_t bit)
{
	const struct kof_parser *vp = obj_region_vocab(o);
	const char *rn = vp && vp->region_name ? vp->region_name(bit) : NULL;
	uint64_t total = 0;
	uint32_t j, n;

	if (!rn)
		return;
	/*
	 * INTO ext2, NOT ext, AND THAT IS NOT A DETAIL.
	 *
	 * `ext` holds the SELECTED region's runs and is the hex pane's entire
	 * sense of where it is - view_map and view_unmap read nothing else. A
	 * tree row is about some OTHER region, and this is drawn every frame,
	 * so resolving into `ext` left it holding whichever region happened to
	 * be drawn last, with n_ext still counting the selected one.
	 *
	 * Everything that maps an offset then mapped through the wrong runs.
	 * "Which mutation block" is where it shows: it takes the byte the menu
	 * was opened on, maps it, and looks for a block covering it - and with
	 * the runs belonging to another region the answer was a byte no block
	 * covers, so the item greyed itself out and the feature looked absent.
	 *
	 * ext2 exists for exactly this and says so where it is declared. This
	 * row and the symbol rows below were the two places still borrowing the
	 * pane's own buffer.
	 */
	{
		struct kof_ext_buf eb = kof_ext_fixed(v->ext2, KOF_SCAN_MAX_EXTENTS);

		n = kof_scan_resolve_range(&o->ctx, bit, &eb);
	}
	for (j = 0; j < n; j++)
		total += v->ext2[j].len;
	if (!total)
		return;
	/* kof_region_label and not the last underscore - see the note on it in
	 * kofinspect.h for what that cost. */
	tree_add(v, o->depth + 1u, i, bit, total, kof_region_label(rn));
}

/*
 * WHAT TO CALL AN OBJECT, IN ONE PLACE.
 *
 * The tree pane and the dashboard both name every object, and they must name it
 * the same way or the two panes describe different things - which they did: the
 * tree said what an object IS and the dashboard said what its FILE is called,
 * so a tar and its first member read as "Tar-any" and "paths.tar" for the same
 * row. This is that decision, made once.
 *
 * What the object IS, not what it is called. The path is on the folder row
 * already, and a sha256 filename repeated in a nineteen column field says
 * nothing. "ELF-x64" does: a signature targets a format and an architecture, so
 * those are the two facts a row exists to carry.
 *
 * "ELF-a32", not "ELF a32". The row is space separated fields, so a field that
 * contains a space reads as two - "//0 ELF a32" looks like three columns and is
 * two. The hyphen is also what the engine uses when it composes a finding name,
 * so the two spell the same object the same way.
 */
/* `out` needs 64 bytes: the widths in the format strings below add up to
 * 57 plus the terminator. */
void obj_label(const struct object *o, char *out, size_t cap)
{
	const char *leaf = kobj_leaf(o->name);
	char what[24];

	/* An object that already knows what its row says - see
	 * struct object.label. */
	if (o->label[0]) {
		snprintf(out, cap, "%s", o->label);
		return;
	}

	/*
	 * WHAT FOLLOWS THE FORMAT IS THE FORMAT'S OWN SECOND FACT.
	 *
	 * For everything with machine code that is the ARCHITECTURE, which is
	 * what the row has always said. A script has no architecture, so it
	 * said "any" - "Script-any" on every php file on the machine, which is
	 * the one word on the row carrying no information.
	 *
	 * Its second fact is the LANGUAGE, and it is the one a reader is
	 * actually looking for: "Script-PHP" says which rules apply, which
	 * subtype a signature must declare, and why the panel is offering the
	 * options it is. ctx->subtype already holds it - see script.h - so this
	 * is naming what the parse already knew.
	 *
	 * Subtype 0 is KOF_SCRIPT_ANY and is a real answer, not a blank: the
	 * file IS a script and no marker in it named the language. The row says
	 * "Script" alone there rather than inventing a second word.
	 */
	if (o->fmt && o->ctx.format == KOF_FMT_SCRIPT)
		snprintf(what, sizeof what, "Script%s%s",
			 o->ctx.subtype ? "-" : "",
			 o->ctx.subtype ? kof_script_type_name(o->ctx.subtype)
					: "");
	else
		snprintf(what, sizeof what, "%s%s%s",
			 o->fmt ? kof_format_name(o->ctx.format) : "Raw",
			 o->fmt ? "-" : "",
			 o->fmt ? kof_arch_name(o->ctx.arch) : "");
	if (o->depth == 0 && o->ctx.format == KOF_EVT_PROC) {
		/*
		 * A PROCESS SAYS SO, AND SAYS WHICH ONE.
		 *
		 * The root of a process view is the snapshot RECORD, so the
		 * format name reads as a file format and the size beside it is
		 * the record's few bytes rather than anything about the
		 * process. Both true, neither what a reader wants from the top
		 * row.
		 *
		 * The OS comes from the RECORD and not from this build,
		 * because a snapshot opened here may have been taken on the
		 * other one - the same reason kof_evt carries its own platform.
		 */
		const struct kof_proc_info *pi = o->info;
		const char *id = o->name;

		while (*id && *id != ':')
			id++;
		if (*id == ':')
			id++;
		snprintf(out, cap, "%s_PROC [%.16s]",
			 (pi && pi->valid && pi->os == KOF_PLAT_WINDOWS)
				 ? "WIN" : "NIX", id);
	} else if (o->depth == 0) {
		snprintf(out, cap, "%s", what);
	} else if (o->payload_of) {
		/*
		 * "//0 Shellcode-x64", in the SAME SHAPE as every other
		 * produced object: the "//<n>" says the engine made this rather
		 * than it having been in the file, and every other child
		 * carries one. Dropping it read as though a Shellcode object
		 * had simply been there - the one thing a reconstruction must
		 * not imply.
		 *
		 * The "ELF-" an ordinary child row carries is dropped, and only
		 * that: the parent row says ELF and this object's own HEADERS
		 * and DATA rows say it again, while "what it is" is the half a
		 * reader cannot get anywhere else.
		 *
		 * NOT "SHELLCODE". Capitals in this tree mean REGION - HEADERS,
		 * CODE, DATA, SYM_IMP - and this is an object. Shouting it
		 * would file a child object under the parent's regions.
		 *
		 * The ARCHITECTURE stays because it is the one fact the parent
		 * does not imply: a 64-bit loader routinely carries a 32-bit
		 * payload.
		 */
		/* The leaf is bounded explicitly rather than left to snprintf:
		 * a container member's name has no length limit and the row
		 * has 48 columns, so the cut is stated where a reader of the
		 * format string can see it. */
		snprintf(out, cap, "//%.24s Shellcode-%s", leaf,
			 o->fmt ? kof_arch_name(o->ctx.arch) : "?");
	} else if (!o->fmt) {
		/*
		 * NO FORMAT WORD, because the absence of one IS the answer.
		 *
		 * This printed "Raw" here, beside a leaf that already says
		 * CONTENT or FONT - so the row read "//1:CONTENT Raw", which
		 * is a name followed by the news that it has no format. On a
		 * row sitting in the region list that is noise: what the reader
		 * needs is what the thing IS, and nothing claiming a format
		 * means no format claimed it.
		 *
		 * The information is not lost, because a format that IS known
		 * still prints below - an attached PE reads "PE-x86_64". So
		 * the presence of the word is the fact, rather than the word
		 * "Raw" being one.
		 */
		snprintf(out, cap, "//%.24s%s", leaf,
			 o->too_big ? "  (not kept)" : "");
	} else {
		snprintf(out, cap, "//%.24s %.18s%s", leaf, what,
			 /* Scanned, but not kept: there is nothing to show and
			  * the row should not pretend there is. */
			 o->too_big ? "  (not kept)" : "");
	}
}

/*
 * What one entry row says: what it IS, and what it is CALLED when anything
 * named it.
 *
 * The kind first and always, because it is the fact the parse is sure of and
 * it is what a scan policy acts on. The name after it when there is one, read
 * out of the object at the range the entry gives - never from a string the
 * entry carries, because it does not carry one: the name is already in the
 * file and a parser has nowhere to build a copy.
 *
 * THE CHAIN, SPELLED OUT, because "stored" and "coded but not by anything
 * this build has" look identical in every other column and lead to opposite
 * conclusions about what a rule will see.
 *
 * Spelled and not abbreviated. This printed a bare "z" first - one letter,
 * meaning "a coding is present", with no legend on the screen or anywhere
 * else. The reader cannot tell what it is, cannot tell whether it matters,
 * and the only way to find out is to ask the person who wrote it. A column
 * wide enough for "zlib" was never the constraint.
 *
 * `+?` at the end is the incomplete flag: there is a step the parse could not
 * express, so running what IS named does not arrive at the original bytes.
 * Shown even when a method is named, because a PARTIAL chain is exactly the
 * case that looks runnable and is not - a Flate stream with a PNG predictor
 * inflates to predictor rows, not to the file. Alone, `?` means the first
 * coding was already inexpressible and nothing could be named at all.
 *
 * Bounded by the buffer and not by trust: name_len came out of the file.
 */
const char *ent_label(const struct object *o, const struct kof_entry *e,
		      char *out, size_t outcap)
{
	const char *kind = kof_entry_kind_name(e->kind);
	char nm[32];
	uint32_t k = 0;

	nm[0] = 0;
	if (e->name_len && o->buf.p &&
	    e->name_off <= o->buf.n && e->name_len <= o->buf.n - e->name_off) {
		uint64_t cap = e->name_len < sizeof nm - 1u ? e->name_len
							   : sizeof nm - 1u;
		uint64_t j;

		/* Printable only. A name is whatever the file says it is, and
		 * this one goes onto a terminal. */
		for (j = 0; j < cap; j++) {
			uint8_t c = o->buf.p[e->name_off + j];

			nm[k++] = (c >= 0x20u && c < 0x7fu) ? (char)c : '.';
		}
	}
	nm[k] = 0;

	{
		char ch[32];
		uint32_t c = 0, j;

		ch[0] = 0;
		for (j = 0; j < 4u && e->coding[j]; j++) {
			const char *w = kof_unp_method_name(e->coding[j]);
			int put = snprintf(ch + c, sizeof ch - c, "%s%s",
					   c ? "+" : "", w);

			if (put <= 0 || (uint32_t)put >= sizeof ch - c)
				break;
			c += (uint32_t)put;
		}
		if (e->flags & KOF_ENT_F_CODED_UNKNOWN)
			snprintf(ch + c, sizeof ch - c, "%s?", c ? "+" : "");

		snprintf(out, outcap, "%s%s%s%s%s", kind,
			 nm[0] ? " " : "", nm,
			 ch[0] ? " " : "", ch);
	}
	return out;
}
