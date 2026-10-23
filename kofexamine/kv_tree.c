#define _GNU_SOURCE
#include "kv.h"




/*
 * A field slid by the panel's horizontal offset.
 *
 * Only the fields that can overrun their column take it - the comment on a
 * matcher or a condition, and the byte dump of a string. Sliding the whole row
 * would move the labels and the buttons out from under the pointer, which is a
 * panel that scrolls away from the mouse that is scrolling it.
 */

/* ---- the tree -------------------------------------------------------------- */

static void tree_add(struct view *v, uint32_t depth, uint32_t obj,
		     uint32_t mask, uint64_t bytes, const char *label)
{
	struct node *n;

	/*
	 * ONE SLOT SHORT, kept for the notice tree_build writes.
	 *
	 * Refusing at the true end would leave nowhere to say that anything was
	 * refused, and the list would simply stop - indistinguishable from a
	 * file that had no more to show. One row is a cheap price for the
	 * difference between "that is all of it" and "that is as much as fits".
	 */
	if (v->n_node + 1u >= MAX_TREE) {
		v->tree_cut = 1;
		return;
	}
	n = &v->node[v->n_node++];
	n->depth = depth;
	n->obj = obj;
	n->mask = mask;
	n->sym = 0;
	/* Cleared here for the reason tree_add_sym's note gives about `sym`: a
	 * slot is reused across rebuilds and `at` is deliberately kept, so a
	 * flag that is only ever SET would stay set on whatever row inherited
	 * the slot. */
	n->ent = 0;
	n->ent_i = 0;
	n->ent_off = n->ent_len = 0;
	n->bytes = bytes;
	snprintf(n->label, sizeof n->label, "%s", label);
}

/*
 * One row of the parser's entry table.
 *
 * Mask ZERO would mean "this row is the object" to node_at, so the row is
 * given KOF_SCAN_ALL and then marked - the same trap tree_add_sym's note
 * describes, arriving from the other direction. `ent` is what every reader
 * tests; the mask is only what keeps a maskless row from being handed back as
 * the whole file.
 */
static void tree_add_ent(struct view *v, uint32_t depth, uint32_t obj,
			 uint32_t index, uint64_t off, uint64_t len,
			 const char *label)
{
	tree_add(v, depth, obj, KOF_SCAN_ALL, len, label);
	if (v->n_node) {
		struct node *n = &v->node[v->n_node - 1u];

		n->ent = 1;
		n->ent_i = index;
		n->ent_off = off;
		n->ent_len = len;
	}
}

/*
 * One region as a single row: every run of it, added up.
 *
 * What the tree has always done, and still the right shape for a region that is
 * one run - or several that a reader has no reason to step through separately.
 */
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

static void region_row(struct view *v, const struct object *o, uint32_t i,
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

/* The symbol row, marked as such. Separate from tree_add because `at` is
 * deliberately NOT cleared there - a row keeps its scroll across a rebuild - so
 * the slot arrives with the last tenant's values in it and a flag that is only
 * ever set would stay set on whatever region row inherited the slot. */
static void tree_add_sym(struct view *v, uint32_t depth, uint32_t obj,
			 uint64_t bytes, uint8_t which, const char *label)
{
	/*
	 * A REAL MASK, because these halves are real scan targets.
	 *
	 * It used to be zero, which said "this row is not something a signature
	 * can be scoped to" - and that was true only for as long as the engine
	 * could not search the block. It can (KOF_SCAN_SYM_IMP in kofsig.h),
	 * and scoping to it is the entire point of splitting the block in two:
	 * a name matched in DATA is any occurrence of those bytes, and the same
	 * name matched in SYM_EXP is the claim that this object exports it.
	 *
	 * Zero also had a second meaning here that it should never have had -
	 * node_at reads a maskless row as THE OBJECT ROW - so a symbol row was
	 * one wrong lookup away from being handed back as the whole file.
	 */
	tree_add(v, depth, obj, which == SYMN_IMP ? KOF_SCAN_SYM_IMP
						  : KOF_SCAN_SYM_EXP,
		 bytes, label);
	if (v->n_node)
		v->node[v->n_node - 1u].sym = which;
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
 * BUILD THE OBJECT WINDOW FOR AN EVENT LOG.
 *
 * obj[0] is the log itself, named KOFT-<system>-<arch> so the row says what
 * produced it rather than repeating the filename the title bar already shows.
 * obj[1..] are the events of the current window, one each, named with the
 * engine's own "//<n>" convention so tree_build nests them under the parent
 * without knowing anything about logs.
 *
 * The index in the name is the event's index IN THE FILE, not in the window -
 * a reader refers to event 40 000 by that number, and a row that renumbered
 * itself as the window moved would be unusable for exactly the thing a log is
 * read for.
 *
 * Each event's buf points INTO THE MAPPING at that record's own extent. Not a
 * copy, and not sizeof the struct: the on-disk length is the head plus this
 * record's own text, so a pane sized from the struct would show the next
 * record's opening bytes as this one's.
 */
/*
 * WHICH VERBS ARE IN THIS LOG, from the mapping and with no I/O.
 *
 * Every record's verb sits at a known offset in its head, and each record says
 * its own text length - so the whole file can be stepped through with pointer
 * arithmetic. A million events is a million additions and no syscalls, which
 * is the difference between asking this question at open and not asking it.
 *
 * Deliberately NOT done by reading records through kofevt_log_read: that
 * copies 512 bytes per event to look at two, and it is the same walk the
 * sparse index already knows how to do.
 */
void log_scan_verbs(struct view *v)
{
	const struct kofevt_log_hdr *h;
	const uint8_t *p, *end;

	v->log_verbs = 0;
	v->log_keep  = 0;
	v->log_events = 0;
	memset(v->log_count, 0, sizeof v->log_count);
	if (!v->log || !v->map)
		return;
	h = kofevt_log_header(v->log);
	if (h->head_size < offsetof(struct kof_evt, text_len) + 2u)
		return;

	p   = (const uint8_t *)v->map + h->hdr_size;
	end = (const uint8_t *)v->map + v->map_len;

	while (p + h->head_size <= end) {
		uint16_t verb = 0, tl = 0;

		memcpy(&verb, p + offsetof(struct kof_evt, verb), sizeof verb);
		memcpy(&tl, p + h->len_off, sizeof tl);
		/*
		 * A CONTINUATION IS NOT A KIND OF EVENT and must not appear in
		 * the filter menu. Offering "cont" as something to tick would
		 * invite a reader to hide the tails while keeping the heads,
		 * which is not a view of anything.
		 */
		if (verb != KOF_EVT_CONT) {
			v->log_events++;
			if (verb < 32u)
				v->log_count[verb]++;
		}
		if (verb < 32u && verb != KOF_EVT_CONT)
			v->log_verbs |= 1u << verb;
		if ((uint32_t)h->head_size + tl > h->rec_size)
			break;              /* the record contradicts itself */
		p += h->head_size + tl;
	}
	/* Everything shown until somebody narrows it. */
	v->log_keep = v->log_verbs;
}

void log_window(struct view *v)
{
	const struct kofevt_log_hdr *h;
	uint64_t i;
	uint32_t n = 1;

	if (!v->log)
		return;
	h = kofevt_log_header(v->log);

	for (i = 0; i < v->n_obj; i++) {
		/*
		 * The buffers are the mapping and are not this loop's, but the
		 * kept answers ARE - see object.carve, which is heap and is
		 * kept so that returning to an object does not read it again.
		 */
		free(v->obj[i].carve);
		memset(&v->obj[i], 0, sizeof v->obj[i]);
	}
	memset(v->pe_of, 0, sizeof v->pe_of);
	v->pe_at = 0;

	snprintf(v->obj[0].name, sizeof v->obj[0].name, "KOFT-%s-%s",
		 kof_evt_platform_name((uint8_t)h->platform),
		 kof_evt_arch_name((uint8_t)h->arch));
	snprintf(v->obj[0].label, sizeof v->obj[0].label, "%.48s",
		 v->obj[0].name);
	v->obj[0].buf   = kof_buf_make(v->map, v->map_len);
	v->obj[0].depth = 0;

	for (i = v->log_first; i < v->log_n && n + 1u < MAX_OBJ; i++) {
		struct object *o = &v->obj[n];
		uint64_t off = 0, end;
		/*
		 * The event's OWN record number, taken before the chunks
		 * behind it are absorbed. `i` walks to the end of the span, so
		 * reading the id off it afterwards named the last chunk - an
		 * event five records in was labelled eleven.
		 */
		uint64_t id = i;
		uint64_t pe_bytes = 0;
		uint32_t len = 0;
		uint16_t vb = 0;

		if (!kofevt_log_extent(v->log, i, &off, &len))
			break;
		if (off + len > v->map_len)
			break;
		/*
		 * AND THAT THE RECORD IS ACTUALLY A struct kof_evt.
		 *
		 * The reads below reach into the mapping at FIXED offsets -
		 * verb at 32, content_len further in - while the only thing
		 * checked here was that the record fits the file. The log is
		 * record-agnostic on purpose: kofevt_log_open takes head_size
		 * from the file and asks only that it is non-zero, no larger
		 * than the record and big enough to hold the length field. A
		 * log declaring a head of two bytes is therefore accepted, and
		 * a two-byte record at the end of the mapping would have had
		 * its `verb` read thirty bytes past it.
		 *
		 * KOF_EVT_HEAD is the fixed part of the record, so one test
		 * covers every field these loops name.
		 */
		if (len < KOF_EVT_HEAD)
			break;

		memcpy(&vb, (const uint8_t *)v->map + off +
			    offsetof(struct kof_evt, verb), sizeof vb);

		/*
		 * A CONTINUATION GETS NO ROW OF ITS OWN.
		 *
		 * It is the tail of the record in front of it, not an event -
		 * see KOF_EVT_CONT. Listed separately it read as a second thing
		 * happening, named "cont", with a fragment of somebody else's
		 * script in it. Reached here it means its parent was filtered
		 * out or the window began in the middle of a chain; either way
		 * there is nothing for it to be the tail of on this screen.
		 */
		if (vb == KOF_EVT_CONT)
			continue;

		/*
		 * FILTERED HERE, so the window holds LOG_WIN events a reader
		 * asked to see rather than LOG_WIN records of which most are
		 * hidden. Filtering after the window was filled would leave a
		 * panel of three rows and no way to reach the fourth match.
		 */
		if (vb < 32u && v->log_keep && !(v->log_keep & (1u << vb)))
			continue;

		/*
		 * THE CHUNKS BEHIND IT BELONG TO THIS ROW.
		 *
		 * They sit immediately after it in the file, so the event's
		 * bytes are one contiguous range and the hex pane can show the
		 * whole thing - head, content, and every continuation - as the
		 * real file bytes they are, with nothing synthesised.
		 */
		end = off + len;
		/*
		 * The submission's total size, summed while the chunks are
		 * walked anyway. The child row needs it BEFORE anything is
		 * materialised - a tree row showing "0 bytes" beside an image
		 * is a row that says the thing is empty.
		 */
		{
			uint16_t cl0 = 0;

			memcpy(&cl0, (const uint8_t *)v->map + off +
				     offsetof(struct kof_evt, content_len),
			       sizeof cl0);
			pe_bytes = cl0;
		}
		while (i + 1u < v->log_n) {
			uint64_t coff = 0;
			uint32_t clen = 0;
			uint16_t cvb = 0;

			if (!kofevt_log_extent(v->log, i + 1u, &coff, &clen))
				break;
			if (coff + clen > v->map_len || clen < KOF_EVT_HEAD)
				break;
			memcpy(&cvb, (const uint8_t *)v->map + coff +
				     offsetof(struct kof_evt, verb),
			       sizeof cvb);
			if (cvb != KOF_EVT_CONT)
				break;
			{
				uint16_t ccl = 0;

				memcpy(&ccl, (const uint8_t *)v->map + coff +
					     offsetof(struct kof_evt,
						      content_len),
				       sizeof ccl);
				pe_bytes += ccl;
			}
			end = coff + clen;
			i++;
		}

		/*
		 * The parent's name is bounded explicitly rather than left to
		 * the compiler to worry about: it is "KOFT-<system>-<arch>",
		 * which is short, but sizeof says 256 and a %s of that plus an
		 * index cannot be proven to fit. Truncating the PARENT half
		 * would break the "//" nesting tree_build reads, so the bound
		 * is on the part that can afford it.
		 */
		snprintf(o->name, sizeof o->name, "%.64s//%llu",
			 v->obj[0].name, (unsigned long long)id);
		o->depth = 1;
		o->buf   = kof_buf_make((const uint8_t *)v->map + off,
				        (size_t)(end - off));
		v->log_idx[n] = id;

		/*
		 * The row's text comes from the RECORD, through the same
		 * kof_evt_label a TUI or a dashboard would use - so a row here
		 * and a row there cannot describe the same event differently.
		 *
		 * The record is copied out of the mapping rather than cast
		 * from it: a log written by a build with a shorter head has its
		 * text at a different offset, and the copy is bounded by what
		 * this build's struct is.
		 */
		{
			struct kof_evt rec;

			memset(&rec, 0, sizeof rec);
			memcpy(&rec, (const uint8_t *)v->map + off,
			       len < sizeof rec ? len : sizeof rec);
			kof_evt_label(&rec, id, o->label, sizeof o->label);
		}
		n++;

		/*
		 * AN EXECUTABLE INSIDE THE EVENT GETS A ROW OF ITS OWN.
		 *
		 * Tested on the RECORD's own first two content bytes, straight
		 * out of the mapping - two bytes, no join, no allocation. The
		 * expensive part is materialising the image, and that waits
		 * until somebody selects the row.
		 *
		 * "MZ" and nothing cleverer. A submission either begins with a
		 * DOS header or it does not; searching the middle of a script
		 * for the letters would offer a child row for every PowerShell
		 * one-liner that happens to contain them.
		 */
		if (n + 1u < MAX_OBJ && vb == KOF_EVT_AMSI_SCAN) {
			uint16_t oo = 0, cl = 0;
			const uint8_t *p8 = (const uint8_t *)v->map + off;

			memcpy(&oo, p8 + offsetof(struct kof_evt, off_object),
			       sizeof oo);
			memcpy(&cl, p8 + offsetof(struct kof_evt, content_len),
			       sizeof cl);
			if (cl >= 2u && oo != KOF_TEXT_NONE &&
			    (uint64_t)h->head_size + oo + 2u <= len &&
			    p8[h->head_size + oo] == 'M' &&
			    p8[h->head_size + oo + 1u] == 'Z') {
				struct object *c = &v->obj[n];

				memset(c, 0, sizeof *c);
				{
					/* Through a copy: the two names are
					 * fields of the same array, and
					 * snprintf may not read and write one
					 * object at once. */
					char pn[224];

					snprintf(pn, sizeof pn, "%.200s",
						 o->name);
					snprintf(c->name, sizeof c->name,
						 "%s//pe", pn);
				}
				/*
				 * NAMED NOW, FROM THE RECORD'S OWN PREFIX.
				 *
				 * It used to say "Img ?" until the row was
				 * clicked, because the image is only joined
				 * when it is picked - and a list where every
				 * carried file is a question mark until you
				 * open it is a list you have to open
				 * everything in.
				 *
				 * It does not need the join. A DOS header, a PE
				 * header and the machine word all sit in the
				 * first few hundred bytes, which is inside the
				 * record's own arena - so the format and the
				 * architecture are answerable from bytes that
				 * are already mapped.
				 *
				 * A THROWAWAY PARSE, and deliberately not kept:
				 * every SIZE it worked out is wrong, because it
				 * was given a prefix. What is taken from it is
				 * the two facts a prefix can answer honestly.
				 * The real parse happens on selection, against
				 * the whole image.
				 */
				{
					struct kof_obj_ctx tc;
					const struct kof_parser *tf;
					void *ti = NULL;
					kof_buf pre = kof_buf_make(
						p8 + h->head_size + oo, cl);

					memset(&tc, 0, sizeof tc);
					tf = kof_inspect_identify(pre, &tc,
								  &ti);
					if (tf)
						snprintf(c->label,
							 sizeof c->label,
							 "%llu Img %s-%s",
							 (unsigned long long)id,
							 kof_format_name(
								tc.format),
							 kof_arch_name(
								tc.arch));
					else
						snprintf(c->label,
							 sizeof c->label,
							 "%llu Img ?",
							 (unsigned long long)id);
					kof_inspect_free(tf, ti);
				}
				c->depth = 2;
				c->ctx.obj_size = pe_bytes;
				v->pe_of[n] = n - 1u;
				v->log_idx[n] = id;
				n++;
			}
		}

		if (n - 1u >= LOG_WIN)
			break;
	}
	/*
	 * Where the next page starts. Taken from the walk rather than computed
	 * from the window's size, because the two disagree the moment a filter
	 * hides a record or a chain of chunks is folded into one row.
	 */
	v->log_next = (i < v->log_n) ? i + 1u : v->log_n;
	v->n_obj = n;
}

/*
 * Move the window so that event `want` is in it, and say whether anything
 * moved.
 *
 * The window is placed so the wanted event is not on its very edge where
 * possible - stepping one row past the end otherwise reloads on every
 * keystroke, which is the difference between scrolling and thrashing.
 */
/*
 * MOVE THE WINDOW TO START AT `first`, and say whether it moved.
 *
 * A WALK, NOT A JUMP, and the difference is the bug this replaced. The old one
 * CENTRED the window on the record asked for - reasonable for "go to event
 * 90000", wrong for "the reader pressed Down at the bottom of the list": it
 * put the next record in the middle of a fresh window, so stepping off the end
 * moved the selection forty-eight events BACKWARDS, into the middle of what
 * had just been read.
 *
 * Turning a page starts the page where the last one ended. That is the only
 * behaviour that composes: a reader holding Down walks the log once, in order,
 * and never sees the same event twice.
 */
int log_window_from(struct view *v, uint64_t first)
{
	if (!v->log || !v->log_n)
		return 0;
	if (first >= v->log_n)
		return 0;
	if (first == v->log_first)
		return 0;

	v->log_first = first;
	log_window(v);
	return 1;
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
static const char *ent_label(const struct object *o,
			     const struct kof_entry *e)
{
	static char out[64];
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

		snprintf(out, sizeof out, "%s%s%s%s%s", kind,
			 nm[0] ? " " : "", nm,
			 ch[0] ? " " : "", ch);
	}
	return out;
}

/*
 * Is the content of this entry present as an object of its own?
 *
 * A linear walk of the object list, which is bounded at MAX_OBJ and is tens of
 * rows in practice. An index would have to be rebuilt whenever a child is
 * added or dropped, and the thing it would save is a walk of a list already
 * being walked to build the tree.
 *
 * `parent` is matched as well as the index, because an entry index is the
 * FORMAT'S number for it and two objects in one tree can both have an entry 4.
 * Matching the index alone hid an entry of one document behind a child of
 * another the moment two PDFs were open at once - which is the shape of bug
 * that only appears on the second file somebody tries.
 */
static int child_of_entry(const struct view *v, uint32_t parent, uint32_t index)
{
	uint32_t i;

	if (index == KOF_ENTRY_NONE)
		return 0;
	for (i = 0; i < v->n_obj; i++) {
		const struct object *o = &v->obj[i];

		if (o->entry_of != index)
			continue;
		/*
		 * The parent of a child is the object one level up whose name
		 * this one's extends. kobj_depth gives the level, and the
		 * list is in walk order - parent before child - so the nearest
		 * shallower object above it is the one.
		 */
		{
			uint32_t k = i;

			while (k > 0) {
				k--;
				if (v->obj[k].depth < o->depth)
					break;
			}
			if (k == parent && v->obj[k].depth < o->depth)
				return 1;
		}
	}
	return 0;
}

void tree_build(struct view *v)
{
	uint32_t i, k;

	v->n_node = 0;
	v->tree_cut = 0;


	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];
		char label[64];

		obj_label(o, label, sizeof label);
		/*
		 * WHERE THE ROW SITS: BESIDE ITS PARENT'S REGIONS WHEN IT HAS
		 * NO STRUCTURE OF ITS OWN.
		 *
		 * A reader's question about a document is flat - what does this
		 * contain - and the answer has two kinds of thing in it:
		 * RANGES THAT ARE IN THE FILE, which are regions, and CONTENT
		 * THAT IS NOT, which is what a decoder produced. The second
		 * cannot be a region: a region is a partition of this object's
		 * own bytes and decoded content has no offset in the file, so
		 * it lives as an object with its own address space. But that is
		 * a fact about addressing, not about what a reader wants to
		 * see, and indenting it a level deeper answered the addressing
		 * question rather than theirs.
		 *
		 * So a child with NO FORMAT of its own - a decoded page stream,
		 * a font program - is drawn at its parent's region level and
		 * reads as one more row in the same list. A child that IS a
		 * format keeps its own level, because it genuinely has a
		 * subtree: an attached PE has headers, code and data of its
		 * own, and flattening it would file those under the PDF's
		 * regions.
		 *
		 * Depth is drawing only - one snprintf pads by it - so this
		 * moves nothing but the eye. Selection, the hex pane and the
		 * search all key off the row's object and mask.
		 */
		{
			/*
			 * ONE COLUMN PER LEVEL, AND A CHILD OBJECT IS A CHILD
			 * OF THE OBJECT - not of the object's last region.
			 *
			 * This used to indent an object by depth * 2 and its
			 * regions by depth * 2 + 1, which puts a child object
			 * TWO columns in while a region goes one. A reader
			 * then sees the root, the root's regions one in, and
			 * the root's children TWO in - reading as though every
			 * child belonged to the region above it. Measured on a
			 * process view: MEM_CMDLINE at column 1 with the
			 * executable at column 2 under it, which says the ELF
			 * is part of the command line.
			 *
			 * With one column per level the tree says what it
			 * means: an object's regions and an object's children
			 * are both one level in, because both belong to IT,
			 * and a child's own regions are one further.
			 *
			 * THE -1 FOR A FORMATLESS CHILD IS GONE WITH IT, and
			 * nothing is lost: it existed to pull a decoded page
			 * stream back to its parent's region level, and at one
			 * column per level that is where a child already is.
			 * The special case was compensating for the doubling.
			 */
			tree_add(v, o->depth, i, 0,
				 o->buf.n ? o->buf.n : o->ctx.obj_size, label);
		}
		/*
		 * The bytes when they are here, the DECLARED size when they are
		 * not. A PE carried inside an event is materialised only when
		 * its row is picked, and until then buf.n is zero - which the
		 * row would otherwise print as the image's size.
		 */
		/* A declared table is as good as a parser here: both say which
		 * kinds of region this object has. See obj_region_bits. */
		if ((!o->fmt && !o->n_rgn) || !v->ext2)
			continue;
		{
			uint32_t bits[KOF_MAX_REGIONS], nb;

			nb = obj_region_bits(o, bits, KOF_MAX_REGIONS);
			for (k = 0; k < nb; k++)
				region_row(v, o, i, bits[k]);
		}
		/*
		 * Last, and only when there is something in it.
		 *
		 * Last because it is not a region: every row above it is an
		 * extent of the file and this one is built, so it reads as the
		 * derived thing it is rather than as another slice. Suppressed
		 * when empty because a row that opens onto nothing is worse
		 * than no row - the reader clicks it to find out, every time.
		 * A stripped file simply has no symbol row, which is itself the
		 * answer.
		 */
		/*
		 * The two symbol rows, last, and each only when it has records.
		 *
		 * Last because they are not regions: every row above is an
		 * extent of the file and these are built, so they read as the
		 * derived things they are rather than as more slices. Sized in
		 * BYTES like every other row - the column means bytes, and a
		 * record count there would read as a very small region.
		 *
		 * Suppressed when empty rather than shown as zero: an object
		 * that imports nothing and one whose symbols could not be read
		 * are different facts, and a row that opens onto nothing
		 * cannot tell them apart. No row at all is the honest answer,
		 * the same one a stripped file gives.
		 */
		{
			uint8_t which[2] = { SYMN_IMP, SYMN_EXP };
			const char *lab[2] = { "SYM_IMP", "SYM_EXP" };
			uint32_t h;

			/* Size and existence both from the engine's extents,
			 * like every region row above. */
			for (h = 0; h < 2u; h++) {
				uint64_t bytes = 0;

				if (!v->ext2)
					break;
				if (!sym_half(o, sym_row_mask(which[h]),
					      v->ext2, KOF_SCAN_MAX_EXTENTS,
					      &bytes))
					continue;
				tree_add_sym(v, o->depth + 1u, i, bytes,
					     which[h], lab[h]);
			}
		}

		/*
		 * THE ENTRY TABLE, LAST, AND ONLY WHEN THE PARSER PUBLISHES ONE.
		 *
		 * The other half of what a parse knows. Every row above answers
		 * "which bytes are what kind"; these answer "what is each thing
		 * this object holds" - and the second question is the one deep
		 * scan acts on, so it is the one a reader has to be able to
		 * check WITHOUT running a scan and dumping the result to disk.
		 * That was the whole gap: the table existed, the engine opened
		 * children from it, and nothing showed it.
		 *
		 * FROM ctx->entries AND NOT FROM THE VIEW STRUCT. The API is
		 * the point - a format's own struct holds this at a different
		 * offset in every format, and reading it here is how this file
		 * grew its own copy of things twice before.
		 *
		 * Guarded on `ext` the way the region rows are, and it is the
		 * EXTENT BUFFER and not an option: without it view_select has
		 * nowhere to put the range when the row is picked, so the row
		 * would exist and open onto nothing. One allocation for the
		 * whole view, so this is a failed-malloc path rather than a
		 * mode - but a row that cannot be looked at should not be
		 * offered, which is the same rule the region rows follow.
		 */
		if (v->ext && o->ctx.entries) {
			const struct kof_entry *tab = NULL;
			uint32_t n = o->ctx.entries(&o->ctx, &tab), e;

			for (e = 0; tab && e < n; e++) {
				/*
				 * ONE ROW PER STREAM, NOT TWO.
				 *
				 * An entry is the stream WHERE IT LIES IN THE
				 * FILE - coded, with its chain and its length.
				 * When something decoded it, there is also an
				 * object holding the CONTENT, and that object's
				 * row is already in this list at this very
				 * level. Two rows for one stream, and the first
				 * of them opens onto compressed noise: a reader
				 * clicking it sees deflate output, which is the
				 * one thing nothing can read.
				 *
				 * So the entry row is dropped when its content
				 * is present, and kept when it is not - an
				 * image nothing opens, a stored attachment, a
				 * coding this build lacks. There the entry IS
				 * the only representation, and it says what the
				 * parse knows: the kind, the name, the chain
				 * and whether the chain can even be run.
				 */
				if (child_of_entry(v, i, tab[e].index))
					continue;
				/*
				 * AND A SCATTERED ENTRY HAS NO RANGE TO OPEN.
				 *
				 * Its bytes are several pieces of the object,
				 * or - for a cabinet's coded folder - not a
				 * range of the object at all, so `off` and
				 * `len` are not a place and the contract says
				 * not to read them. Passed on they would put
				 * the row at offset zero with the DECODED
				 * length, which is a window onto the start of
				 * the file under the entry's name.
				 *
				 * The row stays, because the entry is still
				 * the only thing that says this file is in
				 * there; what it does not do is claim bytes.
				 */
				if (tab[e].flags & KOF_ENT_F_SCATTERED)
					tree_add_ent(v, o->depth + 1u, i,
						     tab[e].index, 0, 0,
						     ent_label(o, &tab[e]));
				else
					tree_add_ent(v, o->depth + 1u, i,
						     tab[e].index, tab[e].off,
						     tab[e].len,
						     ent_label(o, &tab[e]));
			}
		}
	}

	/*
	 * WHAT DID NOT FIT, SAID RATHER THAN LEFT OUT.
	 *
	 * Written past tree_add's guard on purpose - the slot was reserved for
	 * exactly this - and at depth zero so it cannot be read as detail
	 * belonging to the last object shown.
	 *
	 * It is a row that opens onto the whole of object 0, which is normally
	 * the wrong thing for a row to do; the note on suppressing empty rows
	 * elsewhere in this file is about rows that PRETEND to have content.
	 * This one's content is its label, and the alternative is a list that
	 * ends early and says nothing.
	 */
	if (v->tree_cut && v->n_node < MAX_TREE) {
		struct node *n = &v->node[v->n_node++];

		n->depth = 0;
		n->obj = 0;
		n->mask = KOF_SCAN_ALL;
		n->sym = 0;
		n->ent = 0;
		n->ent_i = 0;
		n->ent_off = n->ent_len = 0;
		n->bytes = 0;
		snprintf(n->label, sizeof n->label,
			 "-- more rows than this list holds --");
	}
}
