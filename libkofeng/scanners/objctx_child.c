/*
 * objctx_child.c - declaring and producing a child object.
 *
 * WHAT THIS SERVES: a module that opens, decodes or carves something does not
 * return bytes; it DECLARES a child - its label, kind, entry, format, regions,
 * symbols, what is to be done to it - and emits its bytes, and the engine closes
 * that into one object and queues it. This unit is the whole life of that
 * declaration: the pending set a module writes to (pend_*), the sink its bytes
 * land in, the close (oc_child) that spends everything, and the quota that
 * bounds it (the child cap, the memory ceiling, the per-object cap).
 *
 * THE RULE THAT HOLDS IT TOGETHER: every pending declaration is spent by the
 * child it was written for. oc_kid_push clears the whole pending set (oc_pend_clear);
 * before that was true a second module's child inherited the first one's
 * emulator request and derived_by.
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
 * The most one produced object may hold. Past it, the object is closed with what it
 * has and the REST OF THAT ENTRY IS DROPPED.
 *
 * Truncation, not chunking, and the difference is the whole point. An entry in a
 * container is a file: it has a header at offset zero and everything else in it is
 * located relative to that header. Cutting it at a byte count and calling the
 * remainder a second object produces something that was never a file - it begins
 * mid-structure, nothing identifies it, so no format is recognised, no region is
 * resolved, and every module that names a format is ruled out before it runs. A
 * stream cut into ten pieces is one object that can be parsed and nine that can
 * only be searched as raw bytes.
 *
 * Keeping the head is what makes the truncated object still worth having: a PE's
 * header, imports, entry point and first sections are all at the front, and so is
 * every structure a detector reads. The tail of an object this large is data.
 *
 * What is given up is real and is reported rather than hidden: an entry longer than
 * this is scanned in part, and the object is marked incomplete. That is the honest
 * trade at this size - an object of this size is almost never a packed executable
 * but an installer or an embedded package, whose interesting parts are entries in
 * their own right and are reached by unpacking it, not by scanning its tail.
 *
 * Clamped to half the resident ceiling below, so the object being built and the one
 * being scanned both fit under it.
 */
/*
 * Sixteen megabytes, and every part of that number was measured.
 *
 * It was 64MB, which is not a ceiling on anything real - it is a ceiling on
 * padding. Across 1352 zip entries in 180 real archives the median entry is 255
 * BYTES and the 95th percentile is 92KB, so 64MB is seven hundred times the
 * percentile that matters and 98.4% of entries never come near it.
 *
 * What it was paying for is the case that dominated the corpus and that nobody
 * would call an attack: a PE inflated with a repeated byte so a scanner with a size
 * limit gives up. One measured sample holds 824KB of DEFLATE expanding to exactly
 * 100MB, of which 95.75% is duplicate 4KB blocks - the whole real program is in the
 * first 2.8MB. That is the shape of the problem, and it is not the bomb the budget
 * was written for: no single object is impossibly expensive, they are each merely
 * expensive enough, and there are thousands of them.
 *
 * WHY NOT LESS. 8MB was tried and it is wrong, which is the useful half of this.
 * It decodes 205MB where 64MB decodes 11292MB and it runs the corpus in 6.70s
 * against 11.42s - and it LOSES A DETECTION. A UPX packed miner of 3.9MB unpacks
 * to 13.1MB, which is not padding: its declared expansion is 3.4x where the padded
 * sample's is 127x. A fixed cap cannot tell those apart, so it has to clear the
 * larger of them.
 *
 * At 16MB the corpus keeps all 52 findings, runs in 7.94s, and decodes 670MB of a
 * document set where 64MB decoded 2542MB. That is the whole of the reasoning: as
 * low as it goes without losing anything that was being found.
 *
 * Losing a tail is reported, never silent - an object cut here is marked as not
 * fully examined with a limit as the reason. A caller who would rather have the
 * whole of a large entry raises max_object_bytes and pays the decompression.
 */
#define KOF_OBJ_CAP (16u << 20)

/*
 * Decompression, as a host service.
 *
 * The decoder writes into the same sink an ordinary emit does, so nothing here
 * enforces a limit: oc_emit already refuses past the object cap, past the resident
 * ceiling and past the total budget, and a refusal propagates back as a zero from
 * the sink, which stops the decoder where it stands. That is the property worth
 * stating plainly - a decompression bomb is not recognised, it is simply a stream
 * whose sink stops accepting, and it costs the same as any other stream that is
 * cut short.
 */
/* Close the object being emitted and start the next. */
int oc_child(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_objsrc *kid;
	uint64_t held;

	if (!sc->cur.src)
		return 0;
	if (sc->sink.len + sc->sink.spilled == 0)
		return 0;              /* nothing was emitted; not a child */

	/*
	 * THE HEADER, WRITTEN HERE AND NOWHERE ELSE - see oc_image.
	 *
	 * Last, because a declaration is allowed to be corrected until the
	 * child closes: the entry point is often readable only after the
	 * content exists, and a section's kind only after it has been filled.
	 * mpress_pe.c does both by hand today, through thirteen
	 * kunp_rcstruct_poke calls into a header it wrote itself.
	 */
	if (sc->pend.image && sc->sink.mem && sc->pend.n_sec) {
		const struct kgenome_pe_info *tmpl =
			(const struct kgenome_pe_info *)ctx->file_header;
		uint64_t span = sc->pend.sec[sc->pend.n_sec - 1u].rva +
				sc->pend.sec[sc->pend.n_sec - 1u].vsize;
		uint64_t entry = sc->pend.entry_set ? sc->pend.entry_rva : 0;
		int ok;

		/*
		 * THE IMPORT DIRECTORY FIRST, BECAUSE THE HEADER POINTS AT IT.
		 *
		 * Written here and not when the module declared it, for the
		 * reason the header is written here: a declaration may be
		 * corrected until the child closes, and the table's size is
		 * not settled until the last entry is in.
		 *
		 * BEFORE the header, because the directory entry it sets is
		 * one of the header's own fields - see the pend_dir walk in
		 * kgenome_pe_write_hdr. Written after, the header would carry
		 * whatever the parent's import directory said, which points
		 * into the PACKER's sections and not into this child's.
		 *
		 * A failure here is not silent and not fatal to the child: the
		 * bytes it would have written are untouched - see
		 * kgenome_pe_write_imports, which changes nothing unless the whole
		 * table fits - and no directory is set, so the child goes out
		 * as an image with no imports rather than as one pointing at
		 * a table that is not there.
		 */
		if (sc->pend.imp_set && sc->pend.n_imp) {
			uint64_t n = kgenome_pe_write_imports(sc->sink.mem,
							  sc->sink.len,
							  sc->pend.imp_at,
							  sc->pend.imp,
							  sc->pend.n_imp,
							  sc->pend.imp_pool,
							  sc->pend.imp_pool_n,
							  oc_child_is64(ctx));

			if (n && sc->pend.imp_at < span &&
			    KGENOME_PE_DIR_IMPORT < 16u) {
				sc->pend.dir[KGENOME_PE_DIR_IMPORT].rva =
					sc->pend.imp_at;
				sc->pend.dir[KGENOME_PE_DIR_IMPORT].size = n;
				sc->pend.dir[KGENOME_PE_DIR_IMPORT].set = 1;
			}
		}

		/*
		 * WHAT THE MODULE SAID, OR WHAT THE PARENT IS.
		 *
		 * A packer's child is the parent's own image and the parent's
		 * header is the template; that is the `as_fmt == 0` case and it
		 * is the common one. A DECODER's child is shellcode, which is
		 * no format at all until somebody says which one it should
		 * become - and after the first layer the parent is formatless,
		 * so only the module can say. See `as_format` in kofsig.h.
		 */
		if (sc->pend.as_fmt == KOF_FMT_ELF) {
			int is64 = sc->pend.as_arch == KGENOME_ARCH_X86_64;
			uint16_t mach = (uint16_t)(is64 ? 62u : 3u);

			ok = kgenome_elf_hdr_write(&(const struct kgenome_elf_hdr_req){
					.out = sc->sink.mem,
					.cap = sc->pend.sec[0].rva,
					.is64 = is64,
					.machine = mach,
					.base = sc->pend.as_base,
					.sec = sc->pend.sec,
					.n = sc->pend.n_sec,
					.entry_rva = entry,
					.has_entry = sc->pend.entry_set,
					.image_end = span,
				}) != 0;
		} else {
			/*
			 * AND FOR PE, WHAT THE MODULE SAID ABOUT WIDTH AND
			 * BASE BEATS WHAT THE PARENT IS.
			 *
			 * The ELF arm above has always read pend_as_arch and
			 * pend_as_base; this one read neither, so a module
			 * could declare KOF_FMT_PE and have its architecture
			 * silently ignored. That is not hypothetical - it is
			 * the reason msf_pe.h wrote its own header instead of
			 * declaring one: msfvenom's 64-bit Windows payload is
			 * routinely carried by a PE32 template, and a payload
			 * described as i386 is disassembled and prefiltered as
			 * i386.
			 *
			 * A COPY OF THE TEMPLATE, not a change to the writer's
			 * arguments. The template is the parent's parse and
			 * supplies subsystem, characteristics and the
			 * directories; only the three fields the module
			 * actually spoke about move. Anything but x86 and
			 * x86-64 leaves all three alone - the declaration
			 * cannot say more than the writer can express, and
			 * guessing a machine number for an architecture this
			 * builds no PE for would be inventing one.
			 */
			struct kgenome_pe_info as_pe;
			const struct kgenome_pe_info *use = tmpl;

			if (tmpl && tmpl->valid &&
			    sc->pend.as_fmt == KOF_FMT_PE &&
			    (sc->pend.as_arch == KGENOME_ARCH_X86 ||
			     sc->pend.as_arch == KGENOME_ARCH_X86_64)) {
				int is64 = sc->pend.as_arch == KGENOME_ARCH_X86_64;

				as_pe = *tmpl;
				as_pe.pe32_plus = (uint8_t)(is64 ? 1 : 0);
				as_pe.machine = (uint16_t)(is64 ? 0x8664u
								: 0x014cu);
				if (sc->pend.as_base)
					as_pe.image_base = sc->pend.as_base;
				use = &as_pe;
			}
			ok = (ctx->format == KOF_FMT_PE || sc->pend.as_fmt ==
							   KOF_FMT_PE) &&
			     use && use->valid &&
			     kgenome_pe_write_hdr(sc->sink.mem,
					      sc->pend.sec[0].rva, use,
					      sc->pend.sec, sc->pend.n_sec,
					      entry, span, sc->pend.dir) != 0;
		}
		if (!ok) {
			/*
			 * A declared image whose header will not fit, or whose
			 * parent is not a PE, is not handed over as a headless
			 * blob: the module asked for a file and got none, and
			 * saying so is the only honest answer.
			 */
			oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
			return 0;
		}
	}

	if (sc->sink.fd >= 0) {
		if (!oc_sink_spill(sc))
			return 0;
		held = sc->sink.spilled;
		kid = kof_src_fd(sc->sink.fd, sc->sink.spilled);
		sc->sink.fd = -1;
		sc->sink.spilled = 0;
	} else {
		held = sc->sink.len;
		kid = kof_src_heap(sc->sink.mem, sc->sink.len);
		sc->sink.mem = NULL;
		sc->sink.cap = 0;
	}
	sc->sink.len = 0;
	sc->sink.fixed = 0;
	sc->sink.at = 0;

	/*
	 * The bytes were charged to the sink and are now the child's. Ownership of
	 * the debt moves with them: from here on the count falls when the child is
	 * destroyed, wherever that happens - scanned and released, refused by the
	 * child cap, or abandoned because the walk was aborted.
	 */
	if (!kid) {
		/*
		 * A WHOLE DECODED OBJECT, GONE, AND IT HAS TO SAY SO.
		 *
		 * Unlike oc_kid_push's NULL - which is also how a window refuses
		 * a range - there is no ordinary reason to be here: the bytes
		 * were produced, they were charged, and the only thing that
		 * failed is the constructor. Returning quietly meant a
		 * container whose entry decoded perfectly and then could not
		 * be wrapped was reported as having nothing in it.
		 */
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		oc_scan_release(sc, held);
		return 0;
	}
	kof_src_on_free(kid, oc_scan_release_cb, sc);
	return oc_kid_push(sc, ctx, kid);
}

/*
 * Join a named region into the object being produced.
 *
 * The whole of it is a resolve and a loop of emits, and that is the point: the
 * bytes never leave the host, so a gather is charged, cut and refused by exactly
 * the code that already does that for a decompression. There is no second budget
 * and no path by which a module can assemble more than the ceiling allows.
 *
 * `cap` is the module's own limit and only ever tightens the host's. Applied to
 * what THIS call produces rather than to the object being built, so a module
 * gathering two regions into one child gets a limit per region - which is what a
 * caller means by it, since the sizes it knows are per region.
 *
 * A short return is not an error and is not reported as one: the module asked for a
 * region and got a prefix of it. Whether that is worth calling the object broken is
 * the module's judgement, because only it knows whether the rest mattered.
 */
uint64_t oc_gather(const struct kof_obj_ctx *ctx, uint32_t mask, uint64_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_range *ext = sc->cache.ext_gather;
	kof_buf b = oc_mc(ctx)->data;
	uint64_t done = 0;
	uint32_t n, i;

	if (!oc_can_produce(sc))
		return 0;

	n = kof_scan_resolve_range(ctx, mask, ext);
	for (i = 0; i < n; i++) {
		kof_buf s = kof_slice(b, ext[i].off, ext[i].len);
		uint64_t at = 0;

		while (at < s.n) {
			uint64_t want = s.n - at;

			if (want > EMIT_MAX)
				want = EMIT_MAX;
			if (cap) {
				if (done >= cap)
					return done;
				if (want > cap - done)
					want = cap - done;
			}
			if (!oc_emit(ctx, s.p + at, (uint32_t)want))
				return done;
			at += want;
			done += want;
		}
	}
	return done;
}

/*
 * Name the next child, from bytes in the object being unpacked.
 *
 * A bounded copy and nothing else. Making the bytes safe to print is NOT done here:
 * it happens once, in kof_src_label, which is the only way a label is ever set. Two
 * places doing it would look like defence in depth and would be the opposite - with
 * both present, breaking either one changes nothing observable, so neither is
 * covered by a test and neither can be shown to work. One place, and the test that
 * mutates it fails.
 */
/*
 * What the next child is, from a producer that knows.
 *
 * A store and nothing else; oc_kid_push is what spends it, and clears it whether
 * the child was accepted or refused. Unconditional like oc_name_next: a call
 * with KOF_FMT_UNKNOWN is a producer saying "I will not name this one", and it
 * has to CLEAR what a previous call left rather than leave it standing.
 */
void oc_child_format(const struct kof_obj_ctx *ctx, uint8_t fmt)
{
	kof_scan_of(ctx)->pend.fmt = fmt;
}

/* What the next child is for. Stored and spent by oc_kid_push, like the two
 * beside it, and cleared there whatever happens to the child. */
void oc_child_kind(const struct kof_obj_ctx *ctx, uint32_t kind)
{
	kof_scan_of(ctx)->pend.kind = kind;
}

/* Which entry the next child is the content of. Stored and spent by oc_kid_push,
 * like the two beside it. */
void oc_child_entry(const struct kof_obj_ctx *ctx, uint32_t index)
{
	kof_scan_of(ctx)->pend.entry = index;
}

void oc_note_next(const struct kof_obj_ctx *ctx, const char *text)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	size_t n;

	if (!text || !*text)
		return;
	n = strlen(text);
	if (n > KOF_SRC_LABEL_MAX - 1u)
		n = KOF_SRC_LABEL_MAX - 1u;
	memcpy(sc->pend.label, text, n);
	sc->pend.label[n] = 0;
	sc->pend.label_len = (uint32_t)n;
}

/*
 * The child as it stands: whatever has spilled to the file, then whatever is
 * still in memory behind it. One address space to the module - see
 * produced_read in kofsig.h.
 */
uint32_t oc_produced_read(const struct kof_obj_ctx *ctx, uint64_t off,
				void *out, uint32_t cap)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t total = sc->sink.spilled + sc->sink.len;
	uint32_t got = 0;

	if (!out || !cap || off >= total)
		return 0;
	if ((uint64_t)cap > total - off)
		cap = (uint32_t)(total - off);
	if (off < sc->sink.spilled && sc->sink.fd >= 0) {
		uint64_t n = sc->sink.spilled - off;

		if (n > cap)
			n = cap;
		got = (uint32_t)kof_pos_io(sc->sink.fd, off, out, n, 0);
		if (got < n)
			return got;             /* short read: say so */
	}
	if (got < cap && sc->sink.mem) {
		uint64_t at = off + got - sc->sink.spilled;
		uint32_t n = cap - got;

		if (at + n > sc->sink.len)
			n = (uint32_t)(sc->sink.len - at);
		memcpy((uint8_t *)out + got, sc->sink.mem + at, n);
		got += n;
	}
	return got;
}

/* And the same span, written over. Never past what exists. */
int oc_produced_poke(const struct kof_obj_ctx *ctx, uint64_t off,
			   const void *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint64_t total = sc->sink.spilled + sc->sink.len;
	uint32_t did = 0;

	if (!bytes || !n || off >= total || (uint64_t)n > total - off)
		return 0;
	if (off < sc->sink.spilled && sc->sink.fd >= 0) {
		uint64_t k = sc->sink.spilled - off;

		if (k > n)
			k = n;
		did = (uint32_t)kof_pos_io(sc->sink.fd, off,
					   (void *)(uintptr_t)bytes, k, 1);
		if (did < k)
			return 0;
	}
	if (did < n && sc->sink.mem) {
		uint64_t at = off + did - sc->sink.spilled;

		memcpy(sc->sink.mem + at, (const uint8_t *)bytes + did,
		       n - did);
	}
	return 1;
}


void oc_name_next(const struct kof_obj_ctx *ctx, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	kof_buf s = kof_slice(oc_mc(ctx)->data, off, len);
	uint64_t n;

	sc->pend.label[0] = 0;
	sc->pend.label_len = 0;
	if (!s.n)
		return;
	n = s.n < KOF_SRC_LABEL_MAX - 1u ? s.n : KOF_SRC_LABEL_MAX - 1u;
	memcpy(sc->pend.label, s.p, (size_t)n);
	sc->pend.label[n] = 0;
	sc->pend.label_len = (uint32_t)n;
}

/*
 * Two vtables, differing only in whether the producer entries are there.
 *
 * A detector gets NULLs, so kunp_rcstruct_write and kunp_rcstruct_window answer zero for it, and
 * the rule that only an unpacker produces children is carried by the pointers
 * rather than by a check somewhere that could be missed. Same shape as
 * resolve_scan being NULL when nothing identified the object.
 */


/*
 * The budget for one top level object, inherited by everything below it.
 *
 * Derived from the object rather than fixed: a ratio alone refuses a small archive
 * that legitimately expands, and a constant alone gives a tiny file the same
 * allowance as a large one. The floor and the ratio each cover the other's case.
 *
 * One budget for the whole tree. Per-child limits are how a container full of
 * entries that are each individually reasonable adds up to something that is not.
 */
void kof_scan_budget(struct kof_scanner *sc, uint64_t obj_size,
		     const struct kof_scan_option *opt)
{
	uint64_t want = opt->max_produced_bytes;

	if (want == 0) {
		/* A ratio, floored. Sixty-four rather than the thousand a single
		 * DEFLATE layer can reach: this is the total a tree may do, and an
		 * allowance that large on a large input is no allowance at all. */
		want = obj_size > (UINT64_MAX / 64u) ? UINT64_MAX : obj_size * 64u;
		if (want < (64ull << 20))
			want = 64ull << 20;
	}
	sc->ledger.budget = want;
	sc->ledger.kids_left = opt->max_children ? opt->max_children : 4096u;
	sc->ledger.resident = 0;
	sc->ledger.resident_max = opt->max_resident_bytes ? opt->max_resident_bytes
						   : (128ull << 20);
	/*
	 * Half the ceiling, at most.
	 *
	 * Not the whole of it: while a child is being unpacked, that child is itself
	 * resident, so a cap the size of the ceiling leaves no room to produce
	 * anything and the tree stops one level down. Half means the object in hand
	 * and the object being built both fit, which is what lets a container be
	 * unpacked one entry at a time.
	 */
	sc->ledger.obj_cap = opt->max_object_bytes ? opt->max_object_bytes : KOF_OBJ_CAP;
	if (sc->ledger.obj_cap > sc->ledger.resident_max / 2)
		sc->ledger.obj_cap = sc->ledger.resident_max / 2;
	if (sc->ledger.obj_cap == 0)
		sc->ledger.obj_cap = 1;
	sc->obj.open.broken = 0;
	sc->obj.open.stop = 0;
}

void kof_scan_kids_reset(struct kof_scanner *sc)
{
	uint32_t i;

	for (i = 0; i < sc->child.n; i++)
		kof_src_unref(sc->child.list[i]);
	sc->child.n = 0;
	sc->child.n_views = 0;        /* counted out of n_kids - see scan.h */
	sc->child.n_carved = 0;

	kof_scan_sink_discard(sc);
}

/*
 * WHATEVER A MODULE EMITTED AND NEVER CLOSED IS NOT AN OBJECT, and the memory it
 * was holding stops being resident. Also the cursor: `sink_fixed` and `sink_at`
 * were cleared only when a close SUCCEEDED, so a derived or image sink left open
 * by a module whose close was refused kept its cursor into the next module, whose
 * emits then went through the fixed-size arm to a stale position. Called at the
 * start of every object and of every module's turn.
 */
void kof_scan_sink_discard(struct kof_scanner *sc)
{
	oc_scan_release(sc, sc->sink.len + sc->sink.spilled);
	free(sc->sink.mem);
	sc->sink.mem = NULL;
	sc->sink.len = sc->sink.cap = 0;
	if (sc->sink.fd >= 0)
		close(sc->sink.fd);
	sc->sink.fd = -1;
	sc->sink.spilled = 0;
	sc->sink.fixed = 0;
	sc->sink.at = 0;
}

