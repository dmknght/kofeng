/*
 * scan_walk.c - from a path to objects: the directory walk and the tree of one file.
 *
 * read_dir enumerates, scan_one decides what a name is, scan_tree opens a file as a
 * source and drives the object pipeline (sx_scan_object) over it and over every
 * child that comes back, on an explicit stack of layers and not on the C stack.
 * What it hands to the pipeline is a buffer and a few arguments; what the pipeline
 * hands back is a result and a list of kids. The per-object context that crosses
 * (language, declared regions, wants) is set on the scanner here, before each call -
 * which is the seam the pipeline rewrite replaces with an explicit input.
 */

#define _GNU_SOURCE

#include "scan_int.h"
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


static void scan_one(struct walk *w, const char *path);

int sx_push_dir(struct walk *w, const char *path, size_t len, uint32_t depth)
{
	if (w->n == w->cap) {
		size_t nc = w->cap ? w->cap * 2 : 64;
		struct pending *nv = realloc(w->stack, nc * sizeof *nv);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->stack = nv;
		w->cap = nc;
	}
	w->stack[w->n].path = kof_strdup_n(path, len);
	if (!w->stack[w->n].path) {
		w->out_of_memory = 1;
		return 0;
	}
	w->stack[w->n].depth = depth;
	w->n++;
	return 1;
}

/* Grow the reusable buffer to hold at least `need` bytes including the terminator. */
static int path_reserve(struct walk *w, size_t need)
{
	if (need <= w->path_cap)
		return 1;
	{
		size_t nc = w->path_cap ? w->path_cap : 256;
		char *nv;
		/* The ceiling is what keeps this a loop and not a wrap: nc past
		 * half of size_t doubles to zero, which is not less than `need`
		 * and so ends the loop with a zero-byte allocation. */
		while (nc < need) {
			if (nc > (size_t)-1 / 2u) {
				w->out_of_memory = 1;
				return 0;
			}
			nc *= 2;
		}
		nv = realloc(w->path_buf, nc);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->path_buf = nv;
		w->path_cap = nc;
	}
	return 1;
}

/*
 * HOW DEEP AN OBJECT MAY BE UNPACKED, AND WHY IT IS NOT A NUMBER.
 *
 * A fixed depth is wrong in both directions at once. Twenty layers of a
 * meterpreter payload is twenty passes over about a kilobyte - measured, a
 * twenty deep chain of this engine's own XOR unwrapper is 21 objects and
 * finishes instantly - while twenty layers of a five megabyte archive is a
 * hundred megabytes of decompression, which is the shape a bomb takes. Pick a
 * number that allows the first and it permits the second; pick one that refuses
 * the second and it truncates the first.
 *
 * So the allowance is derived from what a layer COSTS, which is the size of the
 * object about to be opened:
 *
 *     allowed = CHAIN_BYTES / size, clamped to [CHAIN_MIN, CHAIN_MAX]
 *
 *        200 B  ->  64   a stager encoded over and over
 *      64 KB    ->  64   still nothing
 *       1 MB    ->  64
 *       5 MB    ->  12   an archive: roughly the ten to twenty a reader expects
 *      16 MB    ->   4
 *      64 MB+   ->   4   the floor, so something is always looked at
 *
 * The floor matters as much as the ceiling: an object too large to descend far
 * into still gets four levels, because refusing outright would hide a payload
 * behind one big container. And this bounds LAYERS, not bytes - the produced
 * byte budget already bounds those, tree wide, and a second byte limit here
 * would be the same rule written twice.
 */
#define CHAIN_BYTES  (64u << 20)

#define CHAIN_MIN    4u

#define CHAIN_MAX    64u

static uint32_t depth_allowance(uint64_t size)
{
	uint64_t n;

	if (!size)
		return CHAIN_MAX;
	n = (uint64_t)CHAIN_BYTES / size;
	if (n > CHAIN_MAX)
		return CHAIN_MAX;
	if (n < CHAIN_MIN)
		return CHAIN_MIN;
	return (uint32_t)n;
}

struct layer {
	struct kof_objsrc *src;
	char              *name;
	uint32_t           depth;    /* in the object tree, for max_depth */
	/*
	 * PACKER layers only.
	 *
	 * Separate from `depth` because the two answer different questions and
	 * conflating them was the bug: max_depth bounds how far the walk goes and
	 * must count every child, while the heuristic weighs how many times this
	 * program was wrapped to be hidden and must count none of the containers.
	 */
	uint32_t           pdepth;
	int                from_packer;  /* its producer was a packer */
	/* And what that producer DECLARED has to be done to it, with the
	 * lowest --heur level the ask is honoured at. See child_want in
	 * kofsig.h for why a declaration beats anything inferred later. */
	uint32_t           want, want_level;
	/* And where its producer said the program will be - see pend_xw. */
	uint32_t           n_xw;
	uint64_t           xw[KOF_EMU_EXEC_WATCH][2];
	/*
	 * The family its producer decodes, inherited as a prediction, or NULL.
	 *
	 * A pointer into a pack mapping, valid for the life of the engine, so it
	 * is copied here as-is. It is what carries the Meterp guess down through
	 * the formatless intermediate layers a decoder peels, on which no
	 * heuristic fires - see sx_scan_object.
	 */
	const char        *inherit_predict;
	/*
	 * The module that DERIVED this object, or NULL.
	 *
	 * A derived object is the parent with ranges changed, so the module
	 * that changed them must not be offered it again - see `derive` in
	 * kofsig.h. A NEW object carries NULL and is offered to everyone,
	 * which is what keeps a zip inside a zip working.
	 */
	const struct kof_module *derived_by;
};

static void scan_tree(struct walk *w, struct kof_objsrc *root, const char *path)
{
	struct layer *stack = NULL;
	uint32_t n = 0, cap = 0;

	/* The root is not copied into the stack; it is scanned first and its
	 * children seed it. */
	struct kof_objsrc *src = kof_src_ref(root);
	char *name = kof_strdup_n(path, strlen(path));
	uint32_t depth = 0, pdepth = 0;
	int from_packer = 0;            /* the root came off the disk */

	/* The root begins a scope - see the reset beside sx_scan_object below,
	 * which is where the rule is stated. */
	w->sc->verdict_have = 0;
	w->sc->verdict_lvl  = 0;
	/* What the producer of the object in hand declared it needs. Zero for a
	 * root, which nothing produced. */
	uint32_t want_decl = 0, want_decl_level = 0;
	uint32_t xw_decl_n = 0;                 /* a root has no producer */
	uint64_t xw_decl[KOF_EMU_EXEC_WATCH][2];
	const char *inherit = NULL;     /* the root inherits no prediction */
	const struct kof_module *derived_by = NULL;  /* nothing derived a root */

	/* Every other allocation failure in this function sets out_of_memory so
	 * the walk is reported incomplete rather than clean - this one didn't,
	 * which meant an OOM here dropped the root's finding silently instead
	 * (the callback guard below already tolerates a NULL name, so nothing
	 * crashes; it just never gets called). */
	if (!name)
		w->out_of_memory = 1;

	kof_scan_budget(w->sc, kof_src_buf(root).n, w->opt);

	for (;;) {
		struct kof_result res;
		uint32_t i;

		/*
		 * Cleared WHOLE, not field by field.
		 *
		 * It was three assignments, and that is a shape that goes stale
		 * the moment the struct grows: the heuristic fields were added
		 * and every object carried whatever the stack happened to hold,
		 * so a zip reported itself packed. A memset cannot forget a
		 * field, which is the only property worth having here.
		 */
		memset(&res, 0, sizeof res);

		/*
		 * What the producer said this object is the content of, put
		 * where a host can read it. Set before the scan rather than
		 * after, so a callback fired from inside it sees the same
		 * answer as one fired after.
		 */
		res.entry_of = kof_src_entry_of(src);
		res.entry_kind = kof_src_kind_of(src);
		w->sc->cur_src = src;
		/*
		 * And the regions, if the producer named any - the one object
		 * that does is a normalised view. Copied onto the scanner here
		 * because a resolver is reached through ctx, and ctx is built
		 * inside sx_scan_object with nowhere to carry a table of its own.
		 *
		 * Cleared for every other object, unconditionally, because a
		 * table left standing would describe the PREVIOUS object and
		 * the ranges it names are ranges into different bytes.
		 */
		{
			const struct kof_src_region *r = NULL;
			uint32_t g, nr = kof_src_regions_of(src, &r);

			for (g = 0; g < nr; g++)
				w->sc->cur_rgn[g] = r[g];
			w->sc->n_cur_rgn = nr;
			w->sc->cur_rgn_fmt = kof_src_region_fmt_of(src);
		}
		w->sc->cur_lang = (uint8_t)kof_src_lang_of(src,
						&w->sc->cur_subtype,
						&w->sc->cur_subfam);
		kof_scan_kids_reset(w->sc);
		w->sc->cur_want = want_decl;
		w->sc->cur_want_level = want_decl_level;
		w->sc->n_xw = xw_decl_n;
		for (uint32_t q = 0; q < xw_decl_n; q++) {
			w->sc->xw[q].rva = xw_decl[q][0];
			w->sc->xw[q].len = xw_decl[q][1];
		}
		w->sc->cur_derived_by = derived_by;
		/*
		 * A NEW SUBJECT BEGINS A NEW VERDICT - see
		 * kof_scanner.verdict.
		 *
		 * The slot holds one name for one subject, and the question
		 * is where a subject ends. NOT at the file: an object that
		 * came out of a PACKER is the same program decoded, and so
		 * is the normalised view of that - representations, which is
		 * why they share the parent's name rather than each earning
		 * one.
		 *
		 * A CONTAINER'S MEMBER IS NOT A REPRESENTATION. Ten files in
		 * an archive are ten subjects; carrying one member's verdict
		 * into the next would name a clean file after the infected
		 * one beside it, which is the worst thing this slot could do.
		 *
		 * `from_packer` draws most of that line - it is set for what
		 * a packer produced and clear for a root and for a
		 * container's members - but NOT ALL OF IT: a normalised view
		 * has no packer behind it either, and it is the purest
		 * representation there is, the same bytes re-laid-out so a
		 * rule can read them. Clearing the slot for one let the view
		 * take a verdict its own parent already held, which is the
		 * duplicate this whole slot exists to remove.
		 *
		 * So: a root or a container's member, and not a view.
		 */
		if (!from_packer &&
		    kof_src_kind_of(src) != KOF_ENT_NORMALIZED) {
			w->sc->verdict_have = 0;
			w->sc->verdict_lvl  = 0;
		}
		sx_scan_object(w->sc, kof_src_buf(src), w->opt, &res, pdepth,
			    from_packer, inherit, kof_src_fmt_of(src));
		w->sc->cur_src = NULL;
		w->sc->cur_derived_by = NULL;

		/*
		 * A LAYER LEFT UNOPENED IS SAID SO, BEFORE THE VERDICT IS.
		 *
		 * The cost limit below refuses children, and refusing one in
		 * silence would report an object as examined when a layer of it
		 * was never looked at - the failure this engine's budgets are
		 * careful never to produce. Decided here rather than at the push
		 * because the callback has not fired yet: after it, the verdict
		 * for this object is already out.
		 *
		 * It reads as "not fully examined", the same channel a
		 * decompressor uses when its budget runs out, because it is the
		 * same statement: something was produced and nobody looked at it.
		 * Measured over 12.9GB and 60 248 objects it never once fires -
		 * so this is a guard for the file that has not turned up yet
		 * rather than a thing the scan does today.
		 */
		if (!res.broken) {
			for (i = 0; i < w->sc->n_kids; i++)
				if (depth + 1u >
				    depth_allowance(kof_src_buf(w->sc->kids[i]).n)) {
					res.broken = KOF_BROKEN_LIMIT;
					break;
				}
		}

		w->objects++;
		/*
		 * WHETHER THIS FILE PRODUCED ANYTHING, counted where the answer
		 * is - see sx_scan_file, which will not remember a file that did.
		 *
		 * `broken` counts too. An object the scan could not finish is
		 * not a clean one: remembering it would turn a truncated read,
		 * a budget that ran out or a parse that gave up into a
		 * permanent verdict of "nothing here".
		 */
		if (res.n || res.broken)
			w->found++;
		{
			kof_buf ob = kof_src_buf(src);

			/* What the producer declared this object is to be read
			 * with, passed on rather than rebuilt by the host -
			 * see kof_result.syms. */
			res.syms = kof_src_syms_of(src, &res.n_syms);
			/* The module that opened THIS object, recorded by the
			 * engine where it produced a child - see opened_by. */
			res.opened_by = w->sc->opened_by[0] ? w->sc->opened_by
							    : 0;
			/* And which build of it, when the module settled one -
			 * see kof_result.packer_build. */
			res.packer_build = w->sc->packer_build[0]
					 ? w->sc->packer_build : 0;
			/*
			 * A WRAPPER IS NOT REPORTED AS A THING RECOVERED.
			 *
			 * `superseded` is the module saying the child it just
			 * produced is what this object WAS - see `supersede`
			 * in kofsig.h. The object has been scanned by then and
			 * every rule has run on it; what is skipped is the
			 * line that says it came out, because a decryptor and
			 * the ciphertext behind it are not two findings.
			 *
			 * NOT AT THE TOP LEVEL. The file the caller handed
			 * over is reported whatever any module says about it,
			 * and that is checked here rather than trusted to
			 * every module.
			 */
			/*
			 * THE VERDICTS FIRST, each already composed - see
			 * kof_on_event_detected. The engine says which findings it
			 * is reporting and hands them over decoded, so a
			 * host never walks the array deciding for itself.
			 */
			if (w->opt->on_event_detected && name &&
			    !(w->sc->superseded && depth)) {
				uint32_t q;

				for (q = 0; q < res.n; q++)
					if (res.v[q].is_verdict)
						w->opt->on_event_detected(name,
							res.v[q].name,
							&res.v[q],
							w->opt->event_user);
			}
			if (w->cb && name && !(w->sc->superseded && depth) &&
			    w->cb(name, ob.p, ob.n, &res, w->user) != 0)
				w->aborted = 1;
		}

		/*
		 * Take the children before anything else can reset them.
		 *
		 * On max_object_depth and not on max_depth: the second is how
		 * deep into DIRECTORIES the walk goes, and reading it here was
		 * what made one number mean two policies. See the note on both
		 * in kofeng.h.
		 *
		 * The built-in allowance below still applies whatever these
		 * say, so a caller that sets neither is bounded exactly as
		 * before - the difference is only that it can now bound one
		 * axis without the other.
		 */
		if (!w->aborted && !w->out_of_memory &&
		    kof_objtree_may_open(w->opt) &&
		    (!w->opt->max_object_depth ||
		     depth + 1 <= w->opt->max_object_depth)) {
			/*
			 * PUSHED BACKWARDS SO THEY COME OUT FORWARDS.
			 *
			 * The stack is what makes this depth-first without
			 * recursion, and a stack reverses whatever order things
			 * go onto it. Pushed 0..n-1, the children came back
			 * n-1..0 - so an archive listed its last entry first,
			 * and a dropper carrying one payload per architecture
			 * showed them bottom to top in the viewer's tree. The
			 * numbering was right all along; only the order they
			 * were walked in was backwards.
			 */
			for (i = w->sc->n_kids; i-- > 0; ) {
				char kid[512];

				if (n == cap) {
					uint32_t nc = cap ? cap * 2 : 16;
					struct layer *nv = realloc(stack,
								   nc * sizeof *nv);
					if (!nv) {
						w->out_of_memory = 1;
						w->incomplete = 1;
						break;
					}
					stack = nv;
					cap = nc;
				}
				/*
				 * The index AND the name, not the name alone.
				 *
				 * An index on its own says nothing about which of
				 * fifty entries was found, which is what this used
				 * to print. A name on its own is not unique: an
				 * archive may hold two entries with the same name,
				 * and sanitising two different names can collapse
				 * them into one string. Together they are always
				 * exactly one entry.
				 */
				{
					const char *lab =
						kof_src_label_of(w->sc->kids[i]);

					if (*lab)
						snprintf(kid, sizeof kid,
							 "%s//%u:%s",
							 name ? name : "?", i, lab);
					else
						snprintf(kid, sizeof kid, "%s//%u",
							 name ? name : "?", i);
				}
				/*
				 * The cost limit, asked about the CHILD rather
				 * than about this object: what a layer costs is
				 * the size of the thing that layer produced, and
				 * a bomb's children are larger than it is. Asking
				 * the parent would let a small archive hand back
				 * a huge one at full depth, which is the case the
				 * limit exists for.
				 */
				if (depth + 1u >
				    depth_allowance(kof_src_buf(w->sc->kids[i]).n))
					continue;   /* said above, before the verdict */
				stack[n].src = kof_src_ref(w->sc->kids[i]);
				stack[n].name = kof_strdup_n(kid, strlen(kid));
				if (!stack[n].name)
					w->out_of_memory = 1;
				stack[n].depth = depth + 1;
				stack[n].from_packer = w->sc->kid_packer &&
						       w->sc->kid_packer[i];
				stack[n].pdepth = pdepth +
					(stack[n].from_packer ? 1u : 0u);
				stack[n].want = w->sc->kid_want
						? w->sc->kid_want[i] : 0u;
				stack[n].want_level = w->sc->kid_want_level
						? w->sc->kid_want_level[i] : 0u;
				stack[n].n_xw = w->sc->kid_n_xw
						? w->sc->kid_n_xw[i] : 0u;
				if (stack[n].n_xw > KOF_EMU_EXEC_WATCH)
					stack[n].n_xw = KOF_EMU_EXEC_WATCH;
				for (uint32_t q = 0; q < stack[n].n_xw; q++) {
					const uint64_t *sx = w->sc->kid_xw +
						(size_t)i * KOF_EMU_EXEC_WATCH *
						2u + (size_t)q * 2u;

					stack[n].xw[q][0] = sx[0];
					stack[n].xw[q][1] = sx[1];
				}
				stack[n].inherit_predict =
					w->sc->kid_family ? w->sc->kid_family[i]
							  : NULL;
				stack[n].derived_by = w->sc->kid_derived_by
					? w->sc->kid_derived_by[i] : NULL;
				n++;
			}
		} else if ((w->aborted || w->out_of_memory) && w->sc->n_kids > 0) {
			/*
			 * THE CHILDREN THIS OBJECT PRODUCED ARE NOT WALKED, because the
			 * walk was asked to stop (or ran out of memory) - so the file
			 * has parts nobody examined. That is not the policy of a caller
			 * who asked not to descend (heur_off, max_object_depth: "off
			 * means do not descend, never do not look"); it is an
			 * interruption, and a file that was interrupted is not clean -
			 * see sx_scan_file.
			 */
			w->incomplete = 1;
		}
		kof_scan_kids_reset(w->sc);

		/* Nothing to release by hand: a produced source gives its bytes back
		 * when it is destroyed, so every path that drops one - here, the
		 * child cap, an aborted walk - accounts for it without knowing that
		 * it has to. */
		kof_src_unref(src);
		free(name);

		if (w->aborted || n == 0) {
			/* Children still waiting are children nobody looked at. */
			if (n > 0)
				w->incomplete = 1;
			break;
		}
		n--;
		src = stack[n].src;
		name = stack[n].name;
		depth = stack[n].depth;
		pdepth = stack[n].pdepth;
		from_packer = stack[n].from_packer;
		want_decl = stack[n].want;
		want_decl_level = stack[n].want_level;
		xw_decl_n = stack[n].n_xw;
		for (uint32_t q = 0; q < xw_decl_n; q++) {
			xw_decl[q][0] = stack[n].xw[q][0];
			xw_decl[q][1] = stack[n].xw[q][1];
		}
		inherit = stack[n].inherit_predict;
		derived_by = stack[n].derived_by;
	}

	while (n > 0) {
		n--;
		kof_src_unref(stack[n].src);
		free(stack[n].name);
	}
	free(stack);
}

/*
 * THE FILE'S OTHER STREAMS, EACH SCANNED AS A FILE OF ITS OWN.
 *
 * On NTFS a file is a set of named streams and every tool shows one of them.
 * Measured on this machine: a 218KB PE written to `host.txt:hidden.exe` leaves
 * host.txt reporting 29 bytes, and a walk that scans what readdir returns
 * scans those 29 bytes and reports the file clean. The engine could always
 * READ it - naming the stream by hand parsed it correctly as a PE - so what
 * was missing was not a parser, it was anybody ever naming it.
 *
 * SCANNED AS A FILE, NOT AS A CHILD OBJECT. A stream is not something the file
 * contains: it has its own size, its own format and its own verdict, and the
 * only thing it shares with the unnamed stream is a directory entry. So it
 * goes through the same scan_one - cached, unpacked and reported on the same
 * terms as anything else, under a name a person can hand back to the scanner
 * verbatim.
 *
 * IT CALLS scan_one AND NOT sx_scan_file, which is what makes the recursion
 * impossible rather than merely bounded: sx_scan_file is the pair of them and
 * scan_one enumerates nothing, so a stream is never asked for streams of its
 * own. On NTFS that question returns the same list again, so a flag guarding
 * against it would be a flag the correctness depended on.
 */
static void scan_streams(struct walk *w, const char *path)
{
	struct kof_stream_walk sw;
	size_t plen;
	int alias;

	if (w->aborted || w->out_of_memory)
		return;
	if (!kof_streams_open(&sw, path))
		return;

	/*
	 * `path` MAY BE w->path_buf ITSELF, AND path_reserve REALLOCATES IT.
	 *
	 * sx_read_dir builds each entry in w->path_buf and hands that pointer
	 * straight to sx_scan_file, so by the time this runs `path` is very often
	 * the buffer about to be grown. The first version reserved inside the
	 * loop and then did memcpy(w->path_buf, path, plen) - which, on the
	 * one directory deep enough to make the buffer grow, copied from the
	 * block realloc had just freed. It segfaulted on
	 * SysWOW64\WindowsPowerShell and on nothing smaller, which is exactly
	 * how a use-after-free behaves: harmless until the allocator reuses
	 * the page.
	 *
	 * So the aliasing is settled BEFORE anything can move, and the reserve
	 * happens ONCE for the longest suffix the enumeration can produce -
	 * sw.name is a fixed array, so there is a longest. Nothing inside the
	 * loop can reallocate after that.
	 */
	alias = (path == w->path_buf);
	plen = strlen(path);
	if (!path_reserve(w, plen + sizeof sw.name + 1u)) {
		kof_streams_close(&sw);
		return;
	}
	if (!alias)
		memcpy(w->path_buf, path, plen);
	/* When it DID alias, realloc preserved the bytes and they are already
	 * at w->path_buf; `path` is now dangling and is not touched again. */

	while (!w->aborted && !w->out_of_memory && kof_streams_next(&sw)) {
		size_t nl = strlen(sw.name);

		/* Subtraction, so the test cannot be the overflow it guards
		 * against - see the same form throughout this tree. */
		if (plen > w->path_cap || nl + 1u > w->path_cap - plen)
			break;          /* cannot happen; the reserve sized it */
		/*
		 * The suffix is appended verbatim - ":hidden.exe:$DATA" - which
		 * is what the enumeration returned and what CreateFile accepts.
		 * Taking it apart to drop the ":$DATA" would be work with a way
		 * to be wrong and nothing to gain.
		 */
		memcpy(w->path_buf + plen, sw.name, nl + 1u);
		scan_one(w, w->path_buf);
	}
	kof_streams_close(&sw);
}

/*
 * A FILE IS ITS CONTENT AND ITS OTHER STREAMS, and the split is load bearing.
 *
 * scan_one has three early returns - the cache answered, the file would not
 * open, the scan was aborted - and the streams must be enumerated ANYWAY. The
 * cache one is the case that matters: it is keyed on the unnamed stream's size
 * and timestamps, so a file whose content has not changed stays cached while a
 * new alternate stream appears beside it. Enumerating only after a successful
 * scan would make that stream invisible for as long as the cache held, which
 * is exactly the silence this whole feature exists to end.
 */
void sx_scan_file(struct walk *w, const char *path)
{
	scan_one(w, path);
	scan_streams(w, path);
}

static void scan_one(struct walk *w, const char *path)
{
	struct kof_objsrc *src;
	uint64_t before;
	int err = 0;

	/*
	 * ALREADY ANSWERED - asked here because here is where a file is about
	 * to be opened, and the point of asking is not to open it.
	 *
	 * The engine does not know what answers. It calls out and is told yes
	 * or no; the key, where it is kept and whether it can be trusted are
	 * the caller's, for the reasons set out beside cache_seen in kofeng.h.
	 */
	if (w->opt->should_stop &&
	    w->opt->should_stop(w->opt->stop_user)) {
		/* Asked before the file is opened, so a host that has said
		 * stop does not pay for one more mapping. The walk's own
		 * abort flag carries it out of every enclosing loop. */
		w->aborted = 1;
		return;
	}
	if (w->opt->cache_seen &&
	    w->opt->cache_seen(w->opt->cache_user, path)) {
		w->sc->st.cached++;
		return;
	}

	src = kof_src_file(path, &err);
	if (!src) {
		sx_note_unreadable(w);
		return;
	}
	before = w->found;
	w->incomplete = 0;
	scan_tree(w, src, path);
	kof_src_unref(src);
	/*
	 * A STOP THAT ARRIVED DURING THE SCAN. should_stop is asked between modules
	 * and between children, where the callback cannot reach, and when it says
	 * yes the object ends there with whatever it had found so far - which for a
	 * file the detectors had not yet reached is nothing. Nothing found is what
	 * the cache is told to remember, so a cancelled scan wrote the file down as
	 * clean and the next run skipped it for good (tests/unit/scan_logic.c).
	 * Asked again here: a stop that came after the file finished costs one cache
	 * miss, which is cheap beside a detection that is never made.
	 */
	if (w->opt->should_stop && w->opt->should_stop(w->opt->stop_user))
		w->incomplete = 1;

	/*
	 * KEPT ONLY WHEN NOTHING WAS FOUND, and that is the whole rule.
	 *
	 * Storing a file that HAD a finding would mean skipping it next time,
	 * and skipping something already known to be bad is the one outcome a
	 * cache must never produce. It has been produced here before: an
	 * earlier version stored clean unconditionally, so a detection wrote
	 * itself down as clean and every later run passed over it in silence.
	 *
	 * So a file with a finding is simply not remembered. It is scanned
	 * again next time and reported in full, which is also what makes the
	 * stored set a set - present or absent, no verdict to go stale.
	 */
	if (w->opt->cache_keep && w->found == before && !w->incomplete)
		w->opt->cache_keep(w->opt->cache_user, path);
	/*
	 * AND A FINDING IS TOLD TO THE CACHE TOO, which is not the same
	 * statement as not remembering it.
	 *
	 * Not remembering leaves whatever an EARLIER run wrote down. This file
	 * was reached because nothing was consulted or because what was
	 * consulted did not answer for it - and if a set somewhere still calls
	 * it clean, the next run that does trust that set walks past a
	 * detection this one just reported. Saying so is the caller's to act
	 * on; the engine knows no more than the path it just scanned.
	 */
	else if (w->opt->cache_drop && w->found != before)
		w->opt->cache_drop(w->opt->cache_user, path);
}

/* A name the walk could not read, counted so that a subtree that silently
 * vanishes does not read as a subtree with nothing in it. */
void sx_note_unreadable(struct walk *w)
{
	if (w->q)
		w->unreadable++;
	else
		w->sc->st.unreadable++;
}

void sx_read_dir(struct walk *w, const char *dir, uint32_t depth)
{
	size_t dir_len = strlen(dir);
	struct dirent *de;
	DIR *d;

	d = opendir(dir);
	if (!d) {
		/* Unreadable, or a path the system would not accept. Counted, because a
		 * subtree that silently vanishes reads as a subtree with nothing in it. */
		sx_note_unreadable(w);
		return;
	}
	while (!w->aborted && !w->out_of_memory && (de = readdir(d)) != NULL) {
		size_t nl, total;
		struct stat sb;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		nl = strlen(de->d_name);
		total = dir_len + 1 + nl + 1;
		if (!path_reserve(w, total))
			break;
		memcpy(w->path_buf, dir, dir_len);
		w->path_buf[dir_len] = '/';
		memcpy(w->path_buf + dir_len + 1, de->d_name, nl + 1);

		/* lstat, not stat: a symlink is not followed unless asked for, so a link
		 * pointing at an ancestor cannot turn this into a loop. */
		if ((w->opt->follow_symlinks ? stat : kof_lstat)(w->path_buf, &sb) != 0) {
			sx_note_unreadable(w);
			continue;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (!w->opt->recurse_dirs)
				continue;
			if (w->opt->max_depth && depth + 1 > w->opt->max_depth)
				continue;
			sx_push_dir(w, w->path_buf, dir_len + 1 + nl, depth + 1);
		} else if (S_ISREG(sb.st_mode)) {
			if (w->q)
				sx_mtq_put(w, w->path_buf, dir_len + 1 + nl);
			else
				sx_scan_file(w, w->path_buf);
		}
		/* anything else - socket, device, fifo - is not an object */
	}
	closedir(d);
}

/*
 * Scan bytes the caller already has, under a name of their choosing.
 *
 * Same machinery as a file: one source, then scan_tree, which is the part that
 * knows how an object turns into a tree of them. The directory walk above is
 * about finding files; this is about scanning one thing, and the two share
 * everything below that distinction.
 *
 * It exists because a tool that has already scanned a file may want to ask a
 * DIFFERENT question about one object inside it - kofviewer runs the
 * interpreter on a node the reader picked, having built the tree with the
 * static unpackers - and re-scanning the whole file with different options
 * would answer that question about every object instead of the one asked about.
 *
 * The bytes are borrowed, not taken: they must outlive the call.
 */
int kscan_bytes(struct kof_scanner *sc, const void *bytes, uint64_t n,
		   const char *name, const struct kof_scan_option *opt,
		   kof_on_object cb, void *user)
{
	static const struct kof_scan_option conservative;
	struct kof_objsrc *src;
	struct walk w;

	if (!sc || !bytes || !n)
		return KOF_ERR_ARG;
	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.opt  = opt ? opt : &conservative;
	w.cb   = cb;
	w.user = user;

	/*
	 * A window over nothing: kof_src_window needs a parent, and there is no
	 * parent here. kof_src_heap takes ownership of a heap block and this
	 * caller's bytes are not one, so the source is built to borrow - see
	 * kof_src_borrow.
	 */
	src = kof_src_borrow(bytes, n);
	if (!src)
		return KOF_ERR_OPEN;
	scan_tree(&w, src, name ? name : "");
	kof_src_unref(src);
	free(w.path_buf);
	return w.objects ? (int)w.objects : 0;
}

int kof_scan_walk(struct kof_scanner *sc, const char *path,
		  const struct kof_scan_option *opt, kof_on_object cb, void *user)
{
	struct walk w;
	struct stat sb;
	int rc;

	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.opt  = opt;
	w.cb   = cb;
	w.user = user;

	if ((opt->follow_symlinks ? stat : kof_lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;

	if (!S_ISDIR(sb.st_mode)) {
		/* The single-file case needs it too: this name is what the
		 * callback reports and what a repair is keyed on. */
		char sq[4096];

		if (kof_path_squash(path, sq, sizeof sq))
			sx_scan_file(&w, sq);
		else
			sx_scan_file(&w, path);
		rc = w.objects ? (int)w.objects : KOF_ERR_OPEN;
		free(w.path_buf);
		return rc;
	}

	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	{
		/* Both slashes: the trailing one would put "//" in every child
		 * path, and an internal one makes the file itself unspellable
		 * - see path_squash. */
		char sq[4096];
		size_t n = kof_path_squash(path, sq, sizeof sq);

		if (!n || !sx_push_dir(&w, sq, n, 0))
			goto done;
	}

	/* Depth first, by taking from the end: a directory's children are examined
	 * before its siblings, which keeps the pending set small and the page cache
	 * warm. Breadth first would hold a whole level at once. */
	while (!w.aborted && !w.out_of_memory && w.n > 0) {
		struct pending p = w.stack[--w.n];
		sx_read_dir(&w, p.path, p.depth);
		free(p.path);
	}

done:
	while (w.n > 0)
		free(w.stack[--w.n].path);
	free(w.stack);
	free(w.path_buf);
	/* Running out of heap mid-walk is reported, not fatal: what was scanned before
	 * it is still a result, and the caller can tell the walk was cut short. */
	return (int)w.objects;
}
