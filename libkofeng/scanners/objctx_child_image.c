/*
 * objctx_child_image.c - what a module declares about the image of the child it is building: imports, sections, layout, directories, the entry, derive. Split from objctx_child.c; the text is unchanged.
 */

#define _GNU_SOURCE

#include "../kofcore/kofplatform.h"
#include <genotype/image/elf_rebuild.h>

#include "objctx_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * THE PARENT AGAIN, AS THE START OF THIS CHILD - see `derive` in kofsig.h.
 *
 * Emitted through the ordinary path rather than handed over by reference, so
 * every budget sees a child the size of its parent, which is what it is. The
 * saving this is for is not memory - it is that the module stops having to
 * re-emit bytes it is not changing, and with them the sort and the overlap
 * resolution it was getting wrong: measured on strxor_tab_00.c, once dropping
 * 114353 bytes and once letting an over-long record swallow its neighbour.
 *
 * REFUSED ON A SINK THAT IS NOT EMPTY. Deriving says where the child STARTS;
 * after anything has been emitted it would mean appending a copy of the parent
 * to it, which no caller wants and which would silently double an object.
 */
/*
 * ---- WHAT A MODULE DECLARES ABOUT THE CHILD IT IS BUILDING ------------------
 *
 * See `section` in kofsig.h for why these exist rather than a synthesised
 * header. The table is the module's statement; nothing here writes a container
 * out of it, and nothing here parses one back.
 */
#define DECL_SEC_MAX 96u        /* what a PE may declare, which is the most any
				 * producer here has reason to */

/*
 * ---- WHAT THE CHILD IMPORTS - see `import` in kofsig.h ---------------------
 *
 * The bounds are the same kind the section table has and are chosen the same
 * way: from what the one container doing this actually holds. MPRESS's hint
 * list is capped at 32 libraries and 512 functions by the module that reads
 * it, so a table of 1024 entries cannot be filled by it, and the pool holds
 * every name those entries can carry at the 64-byte cap that module enforces.
 * A container that wanted more would be refused here and would say so, which
 * is the behaviour a cap is for.
 */
#define DECL_IMP_MAX  1024u
#define DECL_POOL_MAX (64u * 1024u)

/* Put a string in the pool once, and answer where it is. The same library name
 * arrives once per function it exports, so interning is not an economy - it is
 * what keeps the pool bounded by the NUMBER of names rather than by the number
 * of entries. */
static int imp_intern(struct kof_scanner *sc, const char *s, uint32_t *off)
{
	uint32_t k, n = 0;

	if (!s)
		return 0;
	while (s[n]) {
		if (n >= DECL_POOL_MAX)
			return 0;
		n++;
	}
	if (!n)
		return 0;
	for (k = 0; k + n < sc->pend.imp_pool_n; k++)
		if (!memcmp(sc->pend.imp_pool + k, s, n) && !sc->pend.imp_pool[k + n]) {
			*off = k;
			return 1;
		}
	if (sc->pend.imp_pool_n + n + 1u > DECL_POOL_MAX)
		return 0;
	memcpy(sc->pend.imp_pool + sc->pend.imp_pool_n, s, n);
	sc->pend.imp_pool[sc->pend.imp_pool_n + n] = 0;
	*off = sc->pend.imp_pool_n;
	sc->pend.imp_pool_n += n + 1u;
	return 1;
}

/* Defined with kof_scan_emu_unpack, which is the other caller. */

int oc_import(const struct kof_obj_ctx *ctx, const char *dll,
		    const char *fn, uint32_t ordinal, uint64_t iat_rva)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_imp_decl *d;
	uint32_t dll_off = 0, fn_off = 0;

	if (!sc || !dll || !*dll)
		return 0;
	/* One or the other, never both and never neither - a PE import is a
	 * name or a number, and an entry that is neither describes nothing. */
	if ((ordinal != 0) == (fn != NULL && *fn != 0))
		return 0;
	if (ordinal > 0xffffu)
		return 0;
	if (!sc->pend.imp) {
		sc->pend.imp = calloc(DECL_IMP_MAX, sizeof *sc->pend.imp);
		sc->pend.imp_pool = calloc(DECL_POOL_MAX, 1u);
		if (!sc->pend.imp || !sc->pend.imp_pool)
			return 0;
	}
	/* Refused for room, and said: a module building an import table that
	 * does not fit gets 0 back and the child would otherwise be written with
	 * the entries it did not know were missing. */
	if (sc->pend.n_imp >= DECL_IMP_MAX) {
		oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	if (!imp_intern(sc, dll, &dll_off) ||
	    (!ordinal && !imp_intern(sc, fn, &fn_off))) {
		oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		return 0;
	}

	d = &sc->pend.imp[sc->pend.n_imp++];
	d->iat_rva = iat_rva;
	d->dll_off = dll_off;
	d->fn_off = fn_off;
	d->ordinal = (uint16_t)ordinal;
	d->_pad = 0;
	return 1;
}

uint64_t oc_import_bytes(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->pend.n_imp)
		return 0;
	return kgenome_pe_imports_size(sc->pend.imp, sc->pend.n_imp,
				   sc->pend.imp_pool, sc->pend.imp_pool_n,
				   oc_child_is64(ctx));
}

/*
 * A SECTION NAME, EIGHT BYTES AT MOST, taken from whatever the module passed.
 * The loop it replaces read `name[w]` for w up to seven whatever the string's
 * length, so a short name was read past its terminator at the one boundary this
 * file exists to harden - and the bytes after it were copied into the table.
 */
static void sec_name_copy(char dst[9], const char *name)
{
	unsigned w = 0;

	if (name)
		for (; w < 8u && name[w]; w++)
			dst[w] = name[w];
	for (; w < 9u; w++)
		dst[w] = 0;
}

/*
 * WHERE THE TABLE GOES, AND THE ROOM FOR IT, WHICH IS ONE ACT AND NOT TWO.
 *
 * A module says "put it here" and the engine writes it when the child closes -
 * but the child's buffer was sized before any of this was knowable, from the
 * sections declared to oc_image, and the table does not fit in it.
 *
 * Measured on 445.exe: the payload is cut back to where the image ends by
 * layout_of_produced, leaving about 2.7 KB of the allocation spare, and the
 * table for its 349 imports needs about 7.8 KB. Asking the module to reserve
 * the room itself is not possible - it cannot know the size until it has
 * declared every import, and by then the buffer exists.
 *
 * So the reservation happens here, where both facts are in hand: the engine
 * computed the size and the engine owns the buffer. It is a bounded, one-time
 * growth for a table the engine is about to write, charged to the same budget
 * as everything else, and refused by the same ceilings.
 */
int oc_import_at(const struct kof_obj_ctx *ctx, uint64_t rva)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t need, end;

	if (!sc || !sc->pend.n_imp || !sc->sink.fixed || !sc->sink.mem)
		return 0;
	need = kgenome_pe_imports_size(sc->pend.imp, sc->pend.n_imp,
				   sc->pend.imp_pool, sc->pend.imp_pool_n,
				   oc_child_is64(ctx));
	if (!need)
		return 0;
	end = rva + need;
	if (end < rva)
		return 0;
	if (end > sc->sink.cap) {
		uint64_t add = end - sc->sink.cap;
		uint8_t *mem;

		if (end > sc->ledger.obj_cap || add > sc->ledger.budget ||
		    sc->ledger.resident > sc->ledger.resident_max ||
		    add > sc->ledger.resident_max - sc->ledger.resident) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		mem = realloc(sc->sink.mem, (size_t)end);
		if (!mem) {
			oc_scan_broken(sc, KOF_BROKEN_LIMIT);
			return 0;
		}
		/* The tail has never been written and must not be whatever the
		 * allocator had there: the table does not fill it exactly and
		 * the rest goes into the child. */
		memset(mem + sc->sink.cap, 0, (size_t)add);
		sc->sink.mem = mem;
		sc->sink.cap = (size_t)end;
		sc->ledger.budget -= add;
		scan_charge(sc, add);
	}
	if (end > sc->sink.len)
		sc->sink.len = (size_t)end;
	sc->pend.imp_at = rva;
	sc->pend.imp_set = 1;
	return 1;
}

int oc_section(const struct kof_obj_ctx *ctx, const char *name,
		     uint64_t rva, uint64_t vsize, uint32_t perm,
		     uint32_t flags)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_sec_decl *d;
	uint32_t k;
	unsigned q;

	if (!sc->pend.sec) {
		sc->pend.sec = calloc(DECL_SEC_MAX, sizeof *sc->pend.sec);
		if (!sc->pend.sec)
			return -1;
	}
	if (vsize == 0)
		return -1;
	/*
	 * A REGION IS UNIQUE BY ITS ADDRESS, SO DECLARING IT AGAIN REPLACES IT.
	 *
	 * This is what lets a module LOOK AT WHAT IT BUILT before it says what
	 * the thing is. Declaring up front is unavoidable - the engine sizes
	 * the image from the table - but a declaration made before the content
	 * exists is a guess about the PARENT, and getting that backwards was
	 * measured: vmprotect_pe.c marked its destinations hollow from the
	 * parent's shape, so in a child that had just been filled they still
	 * read as empty, the module accepted the same table again, and
	 * explorer.exe came back as seven identical objects.
	 *
	 * So: declare the layout, fill it, read it back, and say again what is
	 * there. The second word is the one that stands. Nothing is appended
	 * twice and no index has to be carried around for it - the address is
	 * the identity.
	 */
	for (k = 0; k < sc->pend.n_sec; k++)
		if (sc->pend.sec[k].rva == rva) {
			struct kgenome_sec_decl *e = &sc->pend.sec[k];
			unsigned w;

			/* An extent may be corrected, but not over its
			 * neighbour: the table stays ordered and disjoint or
			 * the engine cannot lay the child out from it. */
			if (k + 1u < sc->pend.n_sec &&
			    rva + vsize > sc->pend.sec[k + 1u].rva)
				return -1;
			(void)w;
			sec_name_copy(e->name, name);
			e->vsize = vsize;
			e->perm = perm;
			e->flags = flags;
			return (int)k;
		}
	if (sc->pend.n_sec >= DECL_SEC_MAX)
		return -1;
	d = &sc->pend.sec[sc->pend.n_sec];
	(void)q;
	sec_name_copy(d->name, name);
	d->rva = rva;
	d->vsize = vsize;
	d->perm = perm;
	d->flags = flags;
	return (int)sc->pend.n_sec++;
}

/* Forget the layout - see `sections_reset` in kofsig.h. The image is
 * untouched; a module that clears the table and declares nothing gets a child
 * with no header, which kunp_rcstruct_done refuses. */
int oc_sections_reset(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	sc->pend.n_sec = 0;
	return 1;
}

/* The layout the produced image carries - see `layout_of_produced`. */
uint64_t oc_layout_of_produced(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t entry = 0, base = 0;
	uint32_t n;

	if (!sc->sink.fixed || !sc->sink.mem || !sc->sink.len)
		return 0;
	if (!sc->pend.sec) {
		sc->pend.sec = calloc(DECL_SEC_MAX, sizeof *sc->pend.sec);
		if (!sc->pend.sec)
			return 0;
	}
	n = kgenome_pe_layout_of(kof_buf_make(sc->sink.mem, sc->sink.len),
			     sc->pend.sec, DECL_SEC_MAX, &entry, &base,
			     sc->pend.dir);
	if (!n)
		return 0;
	/*
	 * AND THE CHILD ENDS WHERE ITS LAST SECTION DOES.
	 *
	 * The image was sized from what the container DECLARED, which is not
	 * where the header found inside it says the image ends. Those trailing
	 * bytes are past every section, so no claim covers them and the
	 * partition calls them an OVERLAY - measured on a UPX child, 3233 bytes
	 * of it on a file that carries nothing appended at all.
	 *
	 * Declaring them as padding does not help: padding is deliberately left
	 * out of the section table, so the last claim would still end before
	 * them. They are dropped, which is also what the path this replaces
	 * did - it built a file sized to the sections and never carried the
	 * remainder at all.
	 */
	{
		uint64_t end = sc->pend.sec[n - 1u].rva +
			       sc->pend.sec[n - 1u].vsize;

		/*
		 * ONLY PADDING IS DROPPED. The bytes past the last section were
		 * cut whatever they held, on the strength of one UPX child whose
		 * 3233 were zeros the container's declared size had left behind.
		 * A tail with a non-zero byte in it is not that: it is something
		 * the image carries after its sections, the partition will call it
		 * an overlay, and a rule scoped to OVERLAY is entitled to see it.
		 */
		if (end && end < sc->sink.len) {
			size_t z;

			for (z = (size_t)end; z < sc->sink.len; z++)
				if (sc->sink.mem[z])
					break;
			if (z == sc->sink.len)
				sc->sink.len = (size_t)end;
		}
		sc->pend.n_sec = n;
		sc->pend.entry_rva = entry;
		sc->pend.entry_set = entry ? 1 : 0;
		/* Where the image ends, for a caller with something to put
		 * behind it - see layout_of_produced. */
		return end ? end : (uint64_t)sc->sink.len;
	}
}

/*
 * A directory a module REBUILT, which overrides whatever the parent had - see
 * `child_dir` in kofsig.h.
 */
int oc_child_dir(const struct kof_obj_ctx *ctx, uint32_t idx,
		       uint64_t rva, uint64_t size)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (idx >= 16u)
		return 0;
	sc->pend.dir[idx].rva = rva;
	sc->pend.dir[idx].size = size;
	sc->pend.dir[idx].set = 1;
	return 1;
}

/* The child's entry point, which is often knowable only after its content
 * exists - mpress_pe.c reads it out of a fix-up stub it has just decompressed. */
int oc_child_entry_rva(const struct kof_obj_ctx *ctx, uint64_t rva)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	sc->pend.entry_rva = rva;
	sc->pend.entry_set = 1;
	return 1;
}

/*
 * THE CHILD IS AN IMAGE THE ENGINE LAYS OUT, from the sections just declared.
 *
 * The other half of `section` in kofsig.h. A module declares where things go,
 * asks for the image, writes content at addresses with kunp_rcstruct_poke in whatever
 * order suits it, and the engine writes the header at the close. No module
 * synthesises a container and no engine parses one back.
 *
 * ZERO FILLED, so a section a module never writes to reads as absent rather
 * than as whatever was in the allocator's memory - which matters most for the
 * sections that ARE absent, the hollow ones.
 */
/* Where the next write lands in a fixed sink - see `at` in kofsig.h. */
int oc_at(const struct kof_obj_ctx *ctx, uint64_t off)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	/* Anywhere inside the extent, for the reason oc_emit gives: the cursor
	 * may be placed past what currently counts as the child, because a cut
	 * back to the image's end is not a cut to the space that was paid
	 * for. */
	if (!sc->sink.fixed || off > sc->sink.cap)
		return 0;
	sc->sink.at = off;
	return 1;
}

int oc_image(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t span;
	uint8_t *mem;

	if (!oc_can_produce(sc) || !sc->cur.src)
		return 0;
	if (sc->sink.len || sc->sink.spilled || !sc->pend.n_sec)
		return 0;
	{
		const struct kgenome_sec_decl *last =
			&sc->pend.sec[sc->pend.n_sec - 1u];

		span = last->rva + last->vsize;
	}
	if (!span || span > sc->ledger.budget || span > sc->ledger.obj_cap ||
	    sc->ledger.resident > sc->ledger.resident_max ||
	    span > sc->ledger.resident_max - sc->ledger.resident) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	mem = calloc(1, (size_t)span);
	if (!mem) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	free(sc->sink.mem);
	sc->sink.mem = mem;
	sc->sink.cap = (size_t)span;
	sc->sink.len = (size_t)span;
	sc->sink.fixed = 1;             /* fixed size, written at a cursor */
	sc->sink.at = 0;
	sc->pend.image = 1;
	/*
	 * The format whose vocabulary the declared sections will be turned into
	 * regions with, remembered HERE because this is the last point that has
	 * the context - oc_kid_push, where the table is built, does not. A module
	 * that says otherwise with kunp_rcstruct_as overrides it.
	 */
	sc->pend.img_fmt = ctx->format;

	sc->ledger.budget -= span;
	scan_charge(sc, span);
	return 1;
}

int oc_derive(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf b;
	uint8_t *mem;

	if (!oc_can_produce(sc) || !sc->cur.src)
		return 0;
	if (sc->sink.len || sc->sink.spilled)
		return 0;
	b = kof_src_buf(sc->cur.src);
	if (!b.p || !b.n)
		return 0;

	/* The same three ceilings oc_emit applies, asked once for the whole
	 * copy rather than once per megabyte - a derive is all or nothing, and
	 * half a copy of an object is not a prefix of anything. */
	if (b.n > sc->ledger.budget ||
	    b.n > sc->ledger.obj_cap ||
	    sc->ledger.resident > sc->ledger.resident_max ||
	    b.n > sc->ledger.resident_max - sc->ledger.resident) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}

	/*
	 * ONE ALLOCATION AND ONE COPY, NOT A RUN THROUGH THE SINK.
	 *
	 * Through oc_emit this would cross SINK_SPILL at one megabyte, put the
	 * remaining four and a bit into a temporary file, and turn every later
	 * kunp_rcstruct_poke into a positioned write to a descriptor - on the sample
	 * this was written for, 259 of them. The size is known in full before
	 * the first byte moves, so none of that is necessary: take the memory
	 * once, copy once, and every edit afterwards is a memcpy.
	 *
	 * It also means a derived child never spills, which is deliberate. A
	 * module that derives is editing an object it has already been given
	 * whole, so the memory was there to begin with.
	 */
	mem = malloc((size_t)b.n);
	if (!mem) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	memcpy(mem, b.p, (size_t)b.n);
	free(sc->sink.mem);
	sc->sink.mem = mem;
	sc->sink.cap = (size_t)b.n;
	sc->sink.len = (size_t)b.n;
	sc->sink.fixed = 1;
	sc->sink.at = 0;

	sc->ledger.budget -= b.n;
	scan_charge(sc, b.n);

	/* And the fact that makes it safe to offer this child to everyone
	 * else: the module that derived it does not see it again. */
	sc->pend.derived_by = sc->mod.cur;
	return 1;
}
