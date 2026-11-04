#define _GNU_SOURCE
#include "kv.h"
#include "kv_tree_private.h"

/*
 * A field slid by the panel's horizontal offset.
 *
 * Only the fields that can overrun their column take it - the comment on a
 * matcher or a condition, and the byte dump of a string. Sliding the whole row
 * would move the labels and the buttons out from under the pointer, which is a
 * panel that scrolls away from the mouse that is scrolling it.
 */

/* ---- the tree -------------------------------------------------------------- */

void tree_add(struct view *v, uint32_t depth, uint32_t obj,
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
			 uint64_t off, uint64_t len, const char *label)
{
	tree_add(v, depth, obj, KOF_SCAN_ALL, len, label);
	if (v->n_node) {
		struct node *n = &v->node[v->n_node - 1u];

		n->ent = 1;
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
				char elab[64];

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
					tree_add_ent(v, o->depth + 1u, i, 0, 0,
						     ent_label(o, &tab[e], elab, sizeof elab));
				else
					tree_add_ent(v, o->depth + 1u, i,
						     tab[e].off, tab[e].len,
						     ent_label(o, &tab[e], elab, sizeof elab));
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
		n->ent_off = n->ent_len = 0;
		n->bytes = 0;
		snprintf(n->label, sizeof n->label,
			 "-- more rows than this list holds --");
	}
}
