/*
 * scan.c - process objects.
 *
 * One job in three steps, and the order is the point:
 *
 *   parse         format facts, so the filter has something to filter on
 *   derive        which regions exist - paid once for all modules
 *   filter + run  per module, cheapest test first
 *
 * The derive step is InitCache from the old Kaspersky engine: a small per-object
 * precomputation so each of very many records can be decided with one instruction.
 *
 * Producing the objects is here too, because it is the same job seen from one step out.
 * A file becomes one object; a directory yields many. When there is an unpacker, a
 * container will yield many the same way, through the same stack. What is *not* here:
 * the untrusted boundary a module reads through (objctx.c), and how a search is
 * answered (the matcher).
 */

/* lstat and the dirent walk are POSIX and the tree builds as strict ISO C11, so the
 * feature level has to be asked for - and before any include, or it does nothing. */
#define _POSIX_C_SOURCE 200809L

#include "scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct kof_scanner *kof_scan_of(const struct kof_obj_ctx *ctx)
{
	return (struct kof_scanner *)(void *)(uintptr_t)ctx->priv;
}

struct kof_scanner *kof_scan_new(const struct kof_engine *eng)
{
	struct kof_scanner *sc = calloc(1, sizeof *sc);

	if (!sc)
		return NULL;
	sc->eng = eng;
	sc->sink_fd = -1;   /* 0 is stdin; calloc would have made this a live fd */

	/* The matcher owns the search state: the presence set and the memo are how a
	 * search is answered, not how a scan is bookkept. */
	if (!kof_match_state_init(&sc->m, eng->n_str, eng->memo_size))
		goto fail;
	return sc;

fail:
	kof_scan_free(sc);
	return NULL;
}

void kof_scan_free(struct kof_scanner *sc)
{
	uint32_t i;

	if (!sc)
		return;
	kof_match_state_free(&sc->m);
	kof_scan_kids_reset(sc);
	free(sc->kids);
	for (i = 0; i < KOF_FMT_COUNT; i++)
		free(sc->view[i]);
	free(sc->inf);
	free(sc);
}

const struct kof_stats *kof_scan_stats(const struct kof_scanner *sc)
{
	return &sc->st;
}

/* ---- the byte accessors handed to a module --------------------------------- */

/*
 * Turn a named range into extents.
 *
 * Here rather than in objctx.c because only the parse knows where a region is, and this
 * is the file that ran it. KOF_SCAN_ALL needs no parse at all, which is what lets a
 * module naming only that region run against input nothing identified.
 */
uint32_t kof_scan_resolve_range(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				struct kof_range *ext)
{
	uint32_t n;

	if (scan_mask & KOF_SCAN_ALL) {
		ext[0].off = 0;
		ext[0].len = ctx->obj_size;
		return ctx->obj_size ? 1u : 0u;
	}
	if (!ctx->resolve_scan)
		return 0;
	n = ctx->resolve_scan(ctx, scan_mask, ext, KOF_SCAN_MAX_EXTENTS);
	if (n >= KOF_SCAN_MAX_EXTENTS) {
		/*
		 * The region did not fit, so what follows searches part of it.
		 *
		 * Said rather than swallowed. A buffer that filled exactly is
		 * indistinguishable from one that filled and had more to write, and
		 * the two lead to the same place: a search over some of a region,
		 * reported as a search over the region. That is the one answer this
		 * engine must never give quietly, so it is a limit like any other -
		 * the caller set the size, and the caller can be told it bound.
		 */
		struct kof_scanner *sc = kof_scan_of(ctx);

		if (!sc->broken)
			sc->broken = KOF_BROKEN_LIMIT;
		n = KOF_SCAN_MAX_EXTENTS;
	}
	return n;
}

/* ---- deriving per-object facts --------------------------------------------- */

/*
 * Which regions this object has, as a mask of region bits.
 *
 * Computed once per object, not once per module. Resolving a region walks the segment
 * and section tables and sorts the result, so doing it per module would cost more than
 * running the cheap modules it is meant to save. Done once, the per-module test is a
 * single AND.
 */
static uint32_t regions_present(const struct kof_obj_ctx *ctx, uint32_t wanted)
{
	struct kof_range *ext = kof_scan_of(ctx)->ext;
	uint32_t present = 0, bit;

	if (ctx->obj_size)
		present |= KOF_SCAN_ALL;
	if (!ctx->resolve_scan)
		return present;

	/*
	 * Only the regions some module names. A region nobody asks about does not
	 * need an answer, and one of them is a complement - it builds and sorts the
	 * whole claimed set to produce one range.
	 *
	 * Every bit, not the first sixteen. The ceiling used to be 16 because no
	 * format defined a region above bit 7, which made adding one a silent loss:
	 * the region would never be marked present, so the prefilter would skip
	 * every module that named it, and a detection that does not happen is not
	 * something a test notices. Thirty-one masked tests cost nothing.
	 */
	for (bit = 1; bit < 32; bit++) {
		uint32_t m = 1u << bit;

		if (!(wanted & m))
			continue;
		if (ctx->resolve_scan(ctx, m, ext, KOF_SCAN_MAX_EXTENTS))
			present |= m;
	}
	return present;
}

/*
 * Can this module be ruled out without calling it?
 *
 * Every test reads a field of the module's record against a fact already produced.
 * None touches the blob, which is what makes this a pre-use filter rather than the
 * same conditions written inside the module - those are correct and save nothing,
 * because reaching them costs the call.
 *
 * Absent constraints mean unconstrained, so a module with an empty record runs. The
 * default has to fall that way: over-running costs time, under-running costs
 * detections and would not show up as a failure anywhere.
 */
static int prefilter(const struct kof_module *m, const struct kof_obj_ctx *ctx,
		     uint32_t present, struct kof_stats *st)
{
	st->considered++;

	if (!(m->target_mask & (1u << ctx->format))) {
		st->by_target++;
		return 0;
	}
	if (ctx->obj_size < m->size_min) {
		st->by_size++;
		return 0;
	}
	if (m->arch_mask) {
		/* An architecture outside the bit width cannot be named by a mask, so
		 * a module that constrains architecture does not cover it. */
		if (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))) {
			st->by_arch++;
			return 0;
		}
	}
	/*
	 * What kind of that format, in the format's own vocabulary.
	 *
	 * Safe to test with no idea which format this is, because target_mask was
	 * tested first: a module constraining subtype named one format's values, and
	 * this line is only reached for an object of a format that module declared.
	 * That is what lets KOF_ELF_REL and KOF_PE_DLL share the number 1.
	 */
	if (m->subtype_mask) {
		if (ctx->subtype >= 32 ||
		    !(m->subtype_mask & (1u << ctx->subtype))) {
			st->by_subtype++;
			return 0;
		}
	}
	/* A module that names regions cannot match if none exist here: every search
	 * it performs would be over an empty range. One that names none - scalar
	 * only - has nothing to be excused by, and runs. */
	if (m->scan_mask && !(m->scan_mask & present)) {
		st->by_region++;
		return 0;
	}

	st->ran++;
	return 1;
}

/* ---- naming a finding ------------------------------------------------------ */

/*
 * <target>.<what the author wrote>
 *
 *     ELF-x64.Mirai.Gen
 *     PE-x86.UPX.Gen
 *     Script.Nemucod.Gen
 *
 * The target is composed and not authored: it is what the engine established by
 * parsing, so a module cannot claim a format it was not run against or an
 * architecture the object does not have. What is left for the author is the family
 * and the variant, which is the part that needs a person.
 *
 * Format and architecture are one token joined by a dash rather than two parts.
 * They answer one question - what does this run on - and splitting them made every
 * name carry a separator that never told anyone anything.
 *
 * The operating system is absent on purpose. ELF does not say it, so "Linux" would
 * be a guess wearing the clothes of a fact, which is also why this reads "ELF-x64"
 * and not the "Linux/x64" other engines write.
 *
 * An object with no architecture - a script, or one nothing identified - gets the
 * format alone. A "-any" suffix would be a field describing nothing.
 */
static void finding_str(const struct kof_scanner *sc,
			const struct kof_obj_ctx *ctx,
			const struct kof_module *m, char *out, size_t cap)
{
	const char *nm = kof_db_name(sc->eng, m, sc->rep_name_id);
	const char *fmt = kof_format_name(ctx->format);

	if (ctx->arch == KOF_ARCH_ANY || ctx->format == KOF_FMT_UNKNOWN)
		snprintf(out, cap, "%s.%s", fmt, nm ? nm : "unknown");
	else
		snprintf(out, cap, "%s-%s.%s", fmt, kof_arch_name(ctx->arch),
			 nm ? nm : "unknown");
}

/* ---- identify -------------------------------------------------------------- */

/*
 * The format table.
 *
 * Each collector answers two questions separately: does this object look like
 * mine, and - once a buffer exists - what does it say. The split is what lets the
 * view be allocated only for formats actually met, and it is why sniff takes no
 * buffer.
 *
 * Order is priority. It matters as soon as two formats can claim one object, and
 * writing it down here is cheaper than discovering it is implied by the order of
 * two if statements somewhere.
 */
struct parser {
	uint8_t  format;                       /* enum kof_format */
	uint32_t view_size;
	int (*sniff)(kof_buf);
	int (*parse)(kof_buf, void *view, struct kof_obj_ctx *);
};

static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kof_elf_info *)v, c);
}

static int pe_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pe_parse(b, (struct kof_pe_info *)v, c);
}

static int gzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_gzip_parse(b, (struct kof_gzip_info *)v, c);
}

static int docole_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_docole_parse(b, (struct kof_docole_info *)v, c);
}

static int zip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_zip_parse(b, (struct kof_zip_info *)v, c);
}

static int tar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_tar_parse(b, (struct kof_tar_info *)v, c);
}

static int sevenzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_7z_parse(b, (struct kof_7z_info *)v, c);
}

static int rar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rar_parse(b, (struct kof_rar_info *)v, c);
}

static const struct parser parsers[] = {
	{ KOF_FMT_ELF,  (uint32_t)sizeof(struct kof_elf_info),
	  kof_elf_sniff,  elf_parse_thunk  },
	{ KOF_FMT_PE,   (uint32_t)sizeof(struct kof_pe_info),
	  kof_pe_sniff,   pe_parse_thunk   },
	{ KOF_FMT_GZIP, (uint32_t)sizeof(struct kof_gzip_info),
	  kof_gzip_sniff, gzip_parse_thunk },
	{ KOF_FMT_DOCOLE, (uint32_t)sizeof(struct kof_docole_info),
	  kof_docole_sniff, docole_parse_thunk },
	/*
	 * One row, two formats. The parse decides between ZIP and DOCZIP from the
	 * entry names and sets ctx->format itself, so the format named here is only
	 * which VIEW to allocate - and both share one.
	 */
	{ KOF_FMT_ZIP, (uint32_t)sizeof(struct kof_zip_info),
	  kof_zip_sniff, zip_parse_thunk },
	{ KOF_FMT_TAR, (uint32_t)sizeof(struct kof_tar_info),
	  kof_tar_sniff, tar_parse_thunk },
	{ KOF_FMT_7Z, (uint32_t)sizeof(struct kof_7z_info),
	  kof_7z_sniff, sevenzip_parse_thunk },
	{ KOF_FMT_RAR, (uint32_t)sizeof(struct kof_rar_info),
	  kof_rar_sniff, rar_parse_thunk }
};

/*
 * Decide what the object is and fill the matching view.
 *
 * Nothing is allocated for a format the sniff rejected, and a view once allocated
 * is kept: a directory of ELF binaries allocates one view for the whole walk, and
 * a scanner that never meets a PE never allocates a PE view.
 *
 * An allocation failure leaves the object unidentified rather than failing the
 * scan. That is the same answer an unrecognised format gets, and it is the right
 * one: the object still gets scanned by every module whose target covers unknown.
 */
static void identify(struct kof_scanner *sc, kof_buf buf, struct kof_obj_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < sizeof parsers / sizeof parsers[0]; i++) {
		const struct parser *p = &parsers[i];

		if (!p->sniff(buf))
			continue;
		if (!sc->view[p->format]) {
			sc->view[p->format] = malloc(p->view_size);
			if (!sc->view[p->format])
				return;
		}
		if (p->parse(buf, sc->view[p->format], ctx))
			return;
	}
}

/* ---- the routine ---------------------------------------------------------- */

/*
 * Run the unpackers, once the detectors have had their say.
 *
 * After, not before, and that ordering is a decision rather than a convenience. An
 * archive whose entry names carry "../" is an exploit against whatever will open
 * it, and it has already been named by the time this runs - so unless the caller
 * asked for everything, there is nothing to gain from opening it and a budget to
 * lose. The same policy that already decides whether to keep running detectors
 * decides whether to open the container.
 */
static uint32_t unpack_object(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
			 const struct kof_scan_option *opt,
			 const struct kof_result *res)
{
	uint32_t i;
	int applies = 0;

	if (sc->eng->n_unp == 0)
		return 0;
	if (res->n && !opt->all_matches)
		return 0;

	/*
	 * A fresh attempt for every object.
	 *
	 * Hitting a limit while unpacking one container does not mean the tree is
	 * finished: the memory ceiling is about what is alive at this instant, and
	 * by the time a child is being unpacked its siblings have been scanned and
	 * released, so there is room again. What does carry across the whole tree
	 * is `budget`, which is never reset - that is the bomb defence, and it is
	 * the one that has to be cumulative.
	 *
	 * Sticky exhaustion looked harmless and quietly halved the engine: the
	 * first container to reach the ceiling stopped every container after it.
	 */
	sc->broken = 0;

	kof_mod_unpack_mode(ctx, 1);
	for (i = 0; i < sc->eng->n_unp; i++) {
		const struct kof_module *m = &sc->eng->unp[i];

		/* The same preconditions a detector gets: an unpacker for PE has no
		 * business being entered for an ELF. The region test is skipped -
		 * an unpacker names no region to search. */
		if (!(m->target_mask & (1u << ctx->format)))
			continue;
		if (ctx->obj_size < m->size_min)
			continue;
		if (m->arch_mask &&
		    (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))))
			continue;

		applies = 1;
		if (sc->broken)
			break;          /* nothing left to spend on this tree */

		sc->cur_mod = m;
		m->fn(ctx);
		sc->cur_mod = NULL;
	}
	kof_mod_unpack_mode(ctx, 0);

	/*
	 * "Not fully examined" means both halves: something wanted to open this
	 * object, and the budget was gone. The budget is shared by the whole tree,
	 * so once it runs out every later object inherits the flag - and reporting
	 * that on an object no unpacker would have touched anyway is noise that
	 * makes the real case harder to see.
	 */
	return applies ? sc->broken : 0;
}

static void scan_object(struct kof_scanner *sc, kof_buf buf,
			const struct kof_scan_option *opt, struct kof_result *out)
{
	struct kof_obj_ctx ctx;
	uint32_t present, i;

	memset(&ctx, 0, sizeof ctx);
	kof_mod_attach(&ctx, sc);

	/*
	 * How big the object is, before anything tries to identify it.
	 *
	 * It is a property of the bytes, not of the parse, and leaving it to the
	 * collectors meant an object nothing recognised reported a size of zero.
	 * Everything downstream reads that as an empty file: KOF_SCAN_ALL resolves
	 * to no extents, so regions_present drops it, so the prefilter skips every
	 * module that names it - which is precisely the modules written to run on
	 * anything, the ones with no format header at all. They could not match an
	 * unidentified object, ever, and nothing said so.
	 */
	ctx.obj_size = buf.n;

	kof_match_begin(&sc->m, buf);

	identify(sc, buf, &ctx);

	present = regions_present(&ctx, sc->eng->scan_mask);
	sc->st.objects++;
	sc->st.object_bytes += buf.n;

	for (i = 0; i < sc->eng->n_mods; i++) {
		const struct kof_module *m = &sc->eng->mods[i];

		if (!prefilter(m, &ctx, present, &sc->st))
			continue;

		sc->rep_valid = 0;
		sc->cur_mod   = m;
		m->fn(&ctx);
		sc->cur_mod   = NULL;

		if (!sc->rep_valid)
			continue;

		/* Accumulate. Keeping only the last would drop a finding whenever two
		 * families match one object, and the cap is counted rather than
		 * silently applied. */
		if (out->n < KOF_MAX_FINDINGS) {
			struct kof_finding *f = &out->v[out->n++];
			f->level = sc->rep_level;
			finding_str(sc, &ctx, m, f->name, sizeof f->name);
		} else {
			out->dropped++;
		}

		/*
		 * Stop unless the caller asked for everything. The remaining modules
		 * can only lengthen a list that already says the object is not clean,
		 * and on a database of any size that is most of the work.
		 *
		 * It saves nothing on a clean object, which is nearly every object -
		 * this is a bound on the worst case, not a throughput win.
		 */
		if (!opt->all_matches)
			break;
	}

	/* Before the next kof_match_begin clears them. */
	sc->st.searches       += sc->m.n_calls;
	sc->st.bytes_searched += sc->m.n_bytes_scanned;
	sc->st.gram_bytes     += sc->m.n_bytes_indexed;

	out->broken = unpack_object(sc, &ctx, opt, out);
}

/*
 * Iterative, with its own stack of pending directories.
 *
 * Not recursive, and no depth ceiling: a filesystem may legally be deeper than any
 * number picked here, and putting the limit on the C stack makes the failure mode a
 * stack overflow - a crash, in a library, out of a directory tree. On the heap, running
 * out is reported instead. max_depth is policy for callers who want it, not a safety
 * net.
 *
 * Paths grow rather than living in a fixed buffer, so an over-long one fails visibly
 * instead of being skipped without a word.
 */
struct pending {
	char    *path;
	uint32_t depth;
};

struct walk {
	struct kof_scanner *sc;
	const struct kof_scan_option *opt;
	kof_on_object cb;
	void *user;

	struct pending *stack;
	size_t          n, cap;

	char   *path_buf;     /* reusable, holds the entry currently being examined */
	size_t  path_cap;

	int      aborted;
	int      out_of_memory;
	uint64_t objects;
};

static int push_dir(struct walk *w, const char *path, size_t len, uint32_t depth)
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
		while (nc < need)
			nc *= 2;
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
 * Scan one object and everything it turns out to contain.
 *
 * Iterative, with its own stack, for the same reason the directory walk is: the
 * depth of an object tree is chosen by whoever built the file, and putting it on
 * the C stack makes the failure mode a crash inside a library. It also keeps
 * exactly one parsed view of each format in use at a time - a child parsed while
 * its parent's view was still live would overwrite it, since there is one view per
 * format per scanner.
 *
 * A child holds a reference to whatever its bytes live in, so the parent's mapping
 * survives exactly as long as something still points into it and no longer.
 */
struct layer {
	struct kof_objsrc *src;
	char              *name;
	uint32_t           depth;
};

static void scan_tree(struct walk *w, struct kof_objsrc *root, const char *path)
{
	struct layer *stack = NULL;
	uint32_t n = 0, cap = 0;

	/* The root is not copied into the stack; it is scanned first and its
	 * children seed it. */
	struct kof_objsrc *src = kof_src_ref(root);
	char *name = kof_strdup_n(path, strlen(path));
	uint32_t depth = 0;

	kof_scan_budget(w->sc, kof_src_buf(root).n, w->opt);

	for (;;) {
		struct kof_result res;
		uint32_t i;

		res.n = 0;
		res.dropped = 0;
		res.broken = 0;

		w->sc->cur_src = src;
		kof_scan_kids_reset(w->sc);
		scan_object(w->sc, kof_src_buf(src), w->opt, &res);
		w->sc->cur_src = NULL;

		w->objects++;
		{
			kof_buf ob = kof_src_buf(src);

			if (w->cb && name &&
			    w->cb(name, ob.p, ob.n, &res, w->user) != 0)
				w->aborted = 1;
		}

		/* Take the children before anything else can reset them. */
		if (!w->aborted && !w->out_of_memory &&
		    (!w->opt->max_depth || depth + 1 <= w->opt->max_depth)) {
			for (i = 0; i < w->sc->n_kids; i++) {
				char kid[512];

				if (n == cap) {
					uint32_t nc = cap ? cap * 2 : 16;
					struct layer *nv = realloc(stack,
								   nc * sizeof *nv);
					if (!nv) {
						w->out_of_memory = 1;
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
				stack[n].src = kof_src_ref(w->sc->kids[i]);
				stack[n].name = kof_strdup_n(kid, strlen(kid));
				stack[n].depth = depth + 1;
				n++;
			}
		}
		kof_scan_kids_reset(w->sc);

		/* Nothing to release by hand: a produced source gives its bytes back
		 * when it is destroyed, so every path that drops one - here, the
		 * child cap, an aborted walk - accounts for it without knowing that
		 * it has to. */
		kof_src_unref(src);
		free(name);

		if (w->aborted || n == 0)
			break;
		n--;
		src = stack[n].src;
		name = stack[n].name;
		depth = stack[n].depth;
	}

	while (n > 0) {
		n--;
		kof_src_unref(stack[n].src);
		free(stack[n].name);
	}
	free(stack);
}

static void scan_file(struct walk *w, const char *path)
{
	struct kof_objsrc *src;
	int err = 0;

	src = kof_src_file(path, &err);
	if (!src) {
		w->sc->st.unreadable++;
		return;
	}
	scan_tree(w, src, path);
	kof_src_unref(src);
}

static void read_dir(struct walk *w, const char *dir, uint32_t depth)
{
	size_t dir_len = strlen(dir);
	struct dirent *de;
	DIR *d;

	d = opendir(dir);
	if (!d) {
		/* Unreadable, or a path the system would not accept. Counted, because a
		 * subtree that silently vanishes reads as a subtree with nothing in it. */
		w->sc->st.unreadable++;
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
		if ((w->opt->follow_symlinks ? stat : lstat)(w->path_buf, &sb) != 0) {
			w->sc->st.unreadable++;
			continue;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (!w->opt->recurse_dirs)
				continue;
			if (w->opt->max_depth && depth + 1 > w->opt->max_depth)
				continue;
			push_dir(w, w->path_buf, dir_len + 1 + nl, depth + 1);
		} else if (S_ISREG(sb.st_mode)) {
			scan_file(w, w->path_buf);
		}
		/* anything else - socket, device, fifo - is not an object */
	}
	closedir(d);
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

	if ((opt->follow_symlinks ? stat : lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;

	if (!S_ISDIR(sb.st_mode)) {
		scan_file(&w, path);
		rc = w.objects ? (int)w.objects : KOF_ERR_OPEN;
		free(w.path_buf);
		return rc;
	}

	if (!opt->recurse_dirs)
		return KOF_ERR_OPEN;

	{
		/* A trailing slash would put "//" in every child path. */
		size_t n = strlen(path);
		while (n > 1 && path[n - 1] == '/')
			n--;
		if (!push_dir(&w, path, n, 0))
			goto done;
	}

	/* Depth first, by taking from the end: a directory's children are examined
	 * before its siblings, which keeps the pending set small and the page cache
	 * warm. Breadth first would hold a whole level at once. */
	while (!w.aborted && !w.out_of_memory && w.n > 0) {
		struct pending p = w.stack[--w.n];
		read_dir(&w, p.path, p.depth);
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