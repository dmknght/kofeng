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
	if (!sc)
		return;
	uint32_t i;

	kof_match_state_free(&sc->m);
	for (i = 0; i < KOF_FMT_COUNT; i++)
		free(sc->view[i]);
	free(sc);
}

static void count_unreadable(struct kof_scanner *sc)
{
	sc->st.unreadable++;
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
	return n > KOF_SCAN_MAX_EXTENTS ? KOF_SCAN_MAX_EXTENTS : n;
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
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t present = 0, bit;

	if (ctx->obj_size)
		present |= KOF_SCAN_ALL;
	if (!ctx->resolve_scan)
		return present;

	/* Only the regions some module names. A region nobody asks about does not need
	 * an answer, and one of them is expensive enough that the difference shows. */
	for (bit = 1; bit < 16; bit++) {
		if (!(wanted & (1u << bit)))
			continue;
		if (ctx->resolve_scan(ctx, 1u << bit, ext, KOF_SCAN_MAX_EXTENTS))
			present |= 1u << bit;
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
 * <format>.<arch>.<authored family>.
 *
 * The prefix is composed rather than authored: a module cannot claim a format it was
 * not run against, and one authored name covers every architecture. The operating
 * system is absent on purpose - ELF does not say it, so "Linux" would be a guess
 * wearing the clothes of a fact.
 */
static void finding_str(const struct kof_scanner *sc,
			const struct kof_obj_ctx *ctx,
			const struct kof_module *m, char *out, size_t cap)
{
	const char *nm = kof_db_name(sc->eng, m, sc->rep_name_id);

	snprintf(out, cap, "%s.%s.%s", kof_format_name(ctx->format),
		 kof_arch_name(ctx->arch), nm ? nm : "unknown");
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

static const struct parser parsers[] = {
	{ KOF_FMT_ELF, (uint32_t)sizeof(struct kof_elf_info),
	  kof_elf_sniff, elf_parse_thunk },
	{ KOF_FMT_PE,  (uint32_t)sizeof(struct kof_pe_info),
	  kof_pe_sniff,  pe_parse_thunk  }
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

static uint32_t scan_object(struct kof_scanner *sc, kof_buf buf,
			    const char *name, const struct kof_scan_option *opt,
			    struct kof_result *out)
{
	struct kof_obj_ctx ctx;
	uint32_t present, i, added = 0;

	(void)name;   /* recorded by the caller; the layer tree is its business */

	memset(&ctx, 0, sizeof ctx);
	kof_mod_attach(&ctx, sc);

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
		added++;

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

	return added;
}

/*
 * Map a file read only.
 *
 * mmap rather than read: only the pages a scan actually touches are faulted in, so
 * scoping a search to a region cuts I/O and not merely CPU. It is also what makes an
 * embedded object free later - a child at an offset inside its parent is a window into
 * the same mapping, needing no copy.
 */
struct mapping {
	void    *map;
	uint64_t len;
};

static int map_file(struct mapping *s, const char *path)
{
	struct stat sb;
	int fd;

	s->map = NULL;
	s->len = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return KOF_ERR_OPEN;
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
		close(fd);
		return KOF_ERR_OPEN;
	}
	if (sb.st_size > 0) {
		s->map = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (s->map == MAP_FAILED) {
			s->map = NULL;
			close(fd);
			return KOF_ERR_READ;
		}
	}
	close(fd);
	s->len = (uint64_t)sb.st_size;
	return 0;
}

static void unmap_file(struct mapping *s)
{
	if (s->map)
		munmap(s->map, (size_t)s->len);
	s->map = NULL;
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

static void scan_file(struct walk *w, const char *path)
{
	struct kof_result res;
	struct mapping src;

	res.n = 0;
	res.dropped = 0;

	if (map_file(&src, path) != 0) {
		count_unreadable(w->sc);
		return;
	}

	/*
	 * One layer. When there are archive children this becomes the same stack the
	 * directory walk uses: scan the layer, then push each child a producer yields.
	 */
	scan_object(w->sc, kof_buf_make(src.map, src.len), path, w->opt, &res);
	unmap_file(&src);

	w->objects++;
	if (w->cb && w->cb(path, &res, w->user) != 0)
		w->aborted = 1;
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
		count_unreadable(w->sc);
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
			count_unreadable(w->sc);
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

	if (!opt->recurse_dirs) {
		return KOF_ERR_OPEN;
	}

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