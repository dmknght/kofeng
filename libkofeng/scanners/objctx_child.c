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
#include <kofmod/arj.h>
#include <kofmod/cab.h>
#include <kofmod/chm.h>
#include <kofmod/docole.h>
#include <kofmod/lha.h>
#include <kofmod/pdf.h>
#include <kofmod/rar.h>
#include <kofmod/zip.h>
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
/*
 * Close the object being emitted and start the next: the body of oc_child, shared with
 * the close a cut makes (oc_entry_cut_close), which must not clear the cut latch.
 */
static int child_close(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_objsrc *kid;
	uint64_t held;
	uint32_t cut;

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
		uint64_t span = oc_sec_span(sc);
		uint64_t entry = sc->pend.entry_set ? sc->pend.entry_rva : 0;
		/*
		 * THE ROOM IN FRONT OF THE FIRST SECTION IS THE HEADER'S, and it cannot be more than the buffer
		 * the child lives in. The writers zero what they are given as `cap`, and a table recovered from
		 * the decoded payload names its first section wherever the payload says (engine_defect2 E6):
		 * 0x30000000 made this zero 768 MB of a 12 KB allocation. A header that does not fit is the
		 * refusal below, as it always was - and the room is then 0, not "as much as there is":
		 * clamped to the buffer the writer zeroed the whole decoded payload and the child came out
		 * made, empty and clean.
		 */
		const uint64_t room = sc->pend.sec[0].rva > sc->sink.cap ? 0 : sc->pend.sec[0].rva;
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
			} else {
				/* The child goes out with no imports: said, as the comment above promised
				 * and the code did not (engine_defect2 E3 - a table that grew after its
				 * place was reserved, or imports added after it). */
				oc_scan_limit(sc);
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
					.cap = room,
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
					      room, use,
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
	cut = sc->sink.cut;
	sc->sink.cut = 0;

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
	/* An entry that met its own bound carries the fact itself - see oc_entry_cut. */
	if (cut)
		kof_src_mark_cut(kid, cut);
	return oc_kid_push(sc, ctx, kid);
}

/*
 * THE CLOSE A MODULE ASKS FOR: "this entry is finished".
 *
 * An entry that met its own bound was closed already, at the emit that met it
 * (oc_entry_cut_close), with the bytes decoded so far and a LIMIT of its own. The
 * module's close then finds an empty sink, which used to answer 0 - and every
 * module reads 0 as "the host will take no more" and ENDS ITS WALK, so the entries
 * after the oversize one were never opened (an 84 MB zip with one 91 MB member
 * came back with 6 of its objects). The cut entry's child exists, so the answer is
 * 1. A close that really cannot make a child (quota, allocation) leaves the latch
 * unset and answers 0 as before.
 */
/* KNOWN DEFECT WP2-D13 (2026-10-25, Inference) [sev M]: oc_child (kunp_rcstruct_done) answers 0 for more than "the host will take no more", and bases/decomp/lha.c and arj.c `break` on that 0.
 * Trigger: an lha (-lh6-) or arj (method 1) member that cannot be decoded, first in the archive. Effect: the module walk ends there, the stored members after it
 * are not opened (0 of 2; zip and rar go on) and the root reads DAMAGED. The exact path that answers 0 here is read, not traced; the loops are in the modules (not annotated).
 * Reproducer: tests/unit/ctr_liars.c coded_first (green until fixed). Fix: make the module loops end only on the host's refusal (sticky stop), and go on after a failed member. */
int oc_child(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	int made = child_close(ctx);

	if (!made && sc->sink.refuse == OC_REFUSE_CUT_OPENED)
		made = 1;
	sc->sink.refuse = 0;
	return made;
}

/*
 * THE CLOSE OF AN ENTRY THAT MET ITS OWN BOUND, from the emit that met it: what was
 * decoded so far becomes the child and carries LIMIT, and the sink refuses the rest of
 * this entry (oc_emit) until the module starts the next one (oc_entry_begin, or its own
 * close). Never sticky: nothing here says anything about the entry after it.
 */
void oc_entry_cut_close(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	oc_entry_cut(sc);
	if (child_close(ctx))
		sc->sink.refuse = OC_REFUSE_CUT_OPENED;
	else
		sc->sink.refuse = OC_REFUSE_CUT;
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
	struct kof_ext_buf *eb = kof_scan_ext_buf(sc, 1);
	struct kof_range *ext;
	kof_buf b = oc_mc(ctx)->data;
	uint64_t done = 0;
	uint32_t n, i;

	if (!oc_can_produce(sc))
		return 0;

	n = kof_scan_resolve_range(ctx, mask, eb);
	ext = eb->v;
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

/*
 * HOW LONG A MEMBER'S NAME MAY BE, in bytes as the container wrote it, from the
 * container's own standard. A longer name is not a name that has to be cut to fit: it
 * is INVALID, and a member that carries one is opened without a name and its object
 * is reported damaged (kof_stats.names_invalid). The limit of each, and where it
 * comes from:
 *
 *   ZIP, DocZip  65535  file name length is a 16-bit field (APPNOTE.TXT 4.4.4)
 *   7z           65535  names are UTF-16 units with no field of their own (7zFormat.txt);
 *                       32767 units is the longest path Windows takes, 65534 bytes
 *   RAR          65535  RAR 4 FILE_HEAD name size is 16 bits; RAR 5 writes a vint with
 *                       no stated bound, held to the same
 *   TAR           4096  ustar's fields give 100 + 155 + '/' = 256 (POSIX.1-1988), but
 *                       pax `path` and GNU @LongLink have no field limit: bounded by
 *                       the longest path the system stores, PATH_MAX 4096 with its NUL
 *   CAB            255  szName is at most 255 characters and a NUL ([MS-CAB] 2.3.3,
 *                       KOF_CAB_MAX_NAME 256 with the NUL)
 *   ARJ           2600  the name lives in the basic header, which ARJ bounds at 2600
 *                       bytes (technical.txt, "basic header size")
 *   LHA            255  the level 0/1 name length is one byte (KOF_LHA_MAX_NAME)
 *   OLE             64  a directory entry holds 64 bytes of UTF-16, NUL included, so 31
 *                       characters ([MS-CFB] 2.6.1)
 *   PDF          32767  a string is at most 32767 bytes (ISO 32000-1, Annex C.2; a
 *                       name is 127, but an embedded file's name is a string)
 *   CHM           1024  [MS-ITS] gives the name length as a variable integer with no
 *                       bound, and the parser puts none on it (a name is as long as the
 *                       chunk that holds it, chm_parse.c); 1024 is this host's own, a
 *                       name past it is marked bad on the child, never cut
 *   anything else 4096  PATH_MAX: a name the file system cannot hold is not a name
 *                       (gzip's FNAME and RTF/other producers have no stated limit)
 */
static uint64_t oc_name_limit(uint8_t fmt)
{
	switch (fmt) {
	case KOF_FMT_ZIP:
	case KOF_FMT_DOCZIP:
	case KOF_FMT_7Z:
	case KOF_FMT_RAR:
		return 65535u;
	case KOF_FMT_CAB:
		return 255u;
	case KOF_FMT_ARJ:
		return 2600u;
	case KOF_FMT_LHA:
		return 255u;
	case KOF_FMT_DOCOLE:
		return 64u;
	case KOF_FMT_PDF:
		return 32767u;
	case KOF_FMT_CHM:
		return 1024u;
	default:
		return 4096u;
	}
}

void oc_note_next(const struct kof_obj_ctx *ctx, const char *text)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	size_t n;

	if (!text || !*text)
		return;
	/* Bounded by the pending buffer, not by trusting the module's terminator. */
	n = strnlen(text, KOF_SRC_NAME_MAX + 1u);
	if (n > oc_name_limit(ctx->format)) {
		sc->pend.label[0] = 0;
		sc->pend.label_len = 0;
		sc->pend.name_bad = 1;
		return;
	}
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
	sc->pend.name_bad = 0;
	/*
	 * Judged by the length the CONTAINER gave, not by what is left of it once the
	 * object has clipped the range: a name field that runs past its format's limit
	 * is invalid whether or not the bytes are all there. Nothing is copied for it -
	 * a name cut at a limit looks like a different, valid name, and two members
	 * cut at the same place look like one.
	 */
	if (len > oc_name_limit(ctx->format)) {
		sc->pend.name_bad = 1;
		return;
	}
	if (!s.n)
		return;
	n = s.n;                /* <= len <= the limit <= KOF_SRC_NAME_MAX */
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


/* What a scanner's fair share leaves to the object once its fixed cost and the presence
 * table's allowance (`gram`, given back) are paid: the one figure the share of the objects it
 * produces and the room of the file it reads are both cut from. Needs a budget. */
static uint64_t root_want(const struct kof_scanner *sc, uint64_t *gram_out)
{
	struct kof_budget *b = sc->eng->budget;
	uint64_t fair, gram;
	uint32_t holders;

	holders = atomic_load(&b->holders);
	if (!holders)
		holders = 1u;
	fair = b->cap > b->db ? (b->cap - b->db) / holders : 0;
	gram = fair / 8u;
	if (gram < (1ull << 20))
		gram = 1ull << 20;
	if (gram > (32ull << 20))
		gram = 32ull << 20;
	*gram_out = gram;
	return fair > sc->root_fixed + gram ? fair - sc->root_fixed - gram : 0;
}

/*
 * THIS SCANNER'S SHARE OF THE ENGINE'S MEMORY BUDGET for the object about to be scanned
 * (kofcore/kofbudget.h, points 3 and 4).
 *
 * The share is what is left of the cap after the database, divided among the scanners
 * alive, less this scanner's fixed cost and its presence table (an eighth of the share,
 * between 1 and 32 MiB: the table follows the share instead of its own 32 MiB). It is taken
 * from the engine's count for the length of the object (kof_scan_root_release) and lowers
 * the scanner's resident ceiling when the caller's allowance is the larger of the two - never
 * raises it. A share too small for an object does not stop the scan: the object is refused or
 * loses an optional product through the ordinary ledger, with the ordinary status.
 */
void kof_scan_root_share(struct kof_scanner *sc)
{
	struct kof_budget *b = sc->eng->budget;
	uint64_t gram, want, room, share;
	uint32_t bits;

	if (!b || !sc->root_fixed)
		return;
	kof_scan_root_release(sc);
	want = root_want(sc, &gram);
	/* The file in hand is part of this scanner's fair share, not on top of it: charged on
	 * top, the scanners that took their share last were left a sliver (16 jobs on the corpus:
	 * 40 objects Limit reached became 93, and which ones depended on timing). */
	want = want > sc->file_held ? want - sc->file_held : 0;
	/*
	 * NOT MORE THAN THE LEDGER CAN USE. resident_max, just below, is the smaller of the
	 * allowance and this share, so a share past the allowance is held from the engine and
	 * used by nothing. A lone scanner took the whole fair share all the same - 490 of 512
	 * MiB for a 64 KiB object whose allowance is 128 - and the scanners the host made while
	 * it scanned took what was left: a chain of four, each made inside the previous one's
	 * scan beside an idle one, wanted 1/2 + 1/3 + 1/4 + 1/5 of the room and the fourth was
	 * refused or starved (scan_share.c, formerly ROOT_SHARE_TAKES_ALL_ROOM). Capped, the
	 * ceiling of every object is the same number as before - resident_max is unchanged by
	 * construction, and so is every limit cut from it (obj_cap, the diagnose walk) - and
	 * what the object could not use stays in the budget. The allowance is the host's own
	 * (max_resident_bytes, divided among a parallel walk's workers), or 128 MiB.
	 */
	if (want > sc->ledger.resident_max)
		want = sc->ledger.resident_max;
	room = kof_budget_room(b);
	share = want;
	if (room < share + gram)
		share = room > gram ? room - gram : 0;
	if (kof_budget_charge(b, share + gram))
		sc->root_held = share + gram;
	else
		share = 0;
	if (share < sc->ledger.resident_max)
		sc->ledger.resident_max = share ? share : 1u;
	/* the presence table's cap: 2 bytes a stamp, so 2^(bits+1) <= gram */
	for (bits = 12u; bits < 24u && (1ull << (bits + 2u)) <= gram; bits++)
		;
	sc->match.m.gram_bits = (uint8_t)bits;
}

/*
 * THE ROOM OF A FILE THAT IS READ INTO MEMORY (objsrc.c, kof_src_file), asked before it is
 * read, so before this scanner's share of the budget has been taken for the object. Two
 * figures, both cut from the share the object would have (root_want):
 *
 *   room   a third of it. What a file may take in the heap WHEN a spill file is the
 *          alternative: the file and what is produced from it are resident together, and
 *          a view and one child are each about the size of the file, so a file past a
 *          third leaves the products less than they need. Measured on the 300 PE corpus
 *          with 16 jobs and a disk scratch directory: a half left 181 files broken
 *          (Limit reached), a third 50, a quarter 49, and the mapped file, uncounted, 40.
 *   limit  all of it. What a file may take when there is NO spill file (the default
 *          directory here is a RAM filesystem, where a spill is the same memory): the
 *          file is held whole and the products shrink instead, which is the engine's
 *          own degrade order - an optional product is skipped with a status before an
 *          object is refused - and not the other way round.
 *
 * A file larger than `limit` is read as far as `limit` goes and reported
 * KOF_BROKEN_LIMIT; it is never refused silently and never read past what the budget has.
 * Without a budget (the allocation of it failed when the engine was opened) there is no
 * share to cut: 64 MiB for both, half of the default resident allowance.
 */
void kof_scan_file_room(const struct kof_scanner *sc, uint64_t *room, uint64_t *limit)
{
	uint64_t gram, want;

	if (!sc->eng->budget) {
		*room = *limit = 64ull << 20;
		return;
	}
	want = root_want(sc, &gram);
	*room = want / 3u;
	*limit = want;
}

void kof_scan_root_release(struct kof_scanner *sc)
{
	if (sc->eng->budget && sc->root_held) {
		kof_budget_release(sc->eng->budget, sc->root_held);
		sc->root_held = 0;
	}
}

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
/* The host's scratch directory for this scan, set before anything is read or spilled: the
 * file read decides between the heap and a spill file before the budget of the tree exists. */
void kof_scan_scratch(struct kof_scanner *sc, const struct kof_scan_option *opt)
{
	sc->scratch = opt->scratch_dir && *opt->scratch_dir ? opt->scratch_dir : NULL;
}

/*
 * HOW MANY CHILDREN A TREE MAY HAVE WHEN THE HOST SAYS NOTHING: what the root can hold.
 *
 * It was 4096 for every file, and a zip of 2100 members, a PDF of 5000 streams and an APK
 * of 5242 classes each came back with their members unopened or cut - a quota that is a
 * property of the scanner applied to a property of the file. A container's children are
 * made of its own bytes, and each takes some, so what a file can possibly yield is bounded
 * by its length over the SMALLEST RECORD of any format here, KOF_KID_RECORD_MIN, and that is
 * the default - the floor stays 4096 so a small file, which a bomb is, gets what it always
 * got. The quota is tree-wide, so it is the ROOT's length that sizes it: nothing a child
 * states about itself can raise it.
 *
 * The divisor was 32, "a zip entry is 76 bytes", and it was above the record of three
 * formats: a cab file is 17 bytes plus its name (23 in a measured archive), a chm entry 5
 * plus its name (21), a 7z folder 26 in an archive that does not code its header. Past
 * about 4500-5000 members they came back Limit with children cut (cab opened 4846 of 5000,
 * chm and 7z 4096), a quota that deleted evidence the file really held. The number is now
 * the smallest stored record in this table, each from the format's own header
 * (kofmod/<format>.h, so a parser's bound and this one cannot drift apart):
 *
 *   chm      5   a name length, one name byte, section, offset, length (KOF_CHM_ENTRY_MIN)
 *   pdf     13   "N G obj" and "endobj" (KOF_PDF_OBJECT_MIN)
 *   rar     12   KOF_RAR_ENTRY_MIN
 *   cab     17   the fixed part of a CFFILE and one name byte (KOF_CAB_FILE_MIN)
 *   lha     22   KOF_LHA_HEADER_MIN
 *   arj     40   KOF_ARJ_HEADER_MIN
 *   zip     46   a central record (KOF_ZIP_CENTRAL_MIN); a local header shared by the
 *                records adds nothing
 *   docole 128   a directory entry (KOF_DOCOLE_DIR_ENT)
 *   tar    512   a header block
 *   7z       -   a header may be LZMA-coded and the parser lets it decode to sixteen times
 *                the bytes it is stored in (HDR_DECODE_RATIO), so no stored record bounds
 *                it: a coded header of repeated one-letter names is below one byte a
 *                file. That format is bounded by the ledger (the resident ceiling, which is
 *                what a tree of tiny windows reaches first: a 5-byte-entry chm of 200000
 *                members opened 54049 children and then said Limit, 165 MB peak, 0.25 s,
 *                with the quota raised to the maximum), and by what it says: FOLDERS_FULL
 *                and Limit, never a silent cut.
 *
 * What the quota bounds is therefore a count, and the COST of a bomb of tiny entries is
 * bounded by the other budgets, none of which this number moves: a child that is a window
 * costs no byte of produced budget, so oc_window charges it against the tree's window
 * allowance (kof_scan_ledger.window_left: the root plus the produced-bytes budget, for every
 * container alike), decoded children are charged to the produced-bytes and resident ceilings
 * as ever, and a label comes out of the names quota. Measured on the 5-byte chm above with
 * the divisor at 32, at 5 and with no quota at all: the resident ceiling ends the tree at the
 * same 54049 children whatever the divisor, so lowering it to 5 changes what a legitimate
 * archive gets and not what a bomb costs. A host that wants a tighter or looser tree sets
 * max_children.
 */
#define KID_MIN2(a, b) ((a) < (b) ? (a) : (b))
#define KOF_KID_RECORD_MIN                                                       \
	KID_MIN2(KOF_CHM_ENTRY_MIN,                                              \
	KID_MIN2(KOF_RAR_ENTRY_MIN,                                              \
	KID_MIN2(KOF_PDF_OBJECT_MIN,                                             \
	KID_MIN2(KOF_CAB_FILE_MIN,                                               \
	KID_MIN2(KOF_LHA_HEADER_MIN,                                             \
	KID_MIN2(KOF_ARJ_HEADER_MIN,                                             \
	KID_MIN2(KOF_ZIP_CENTRAL_MIN, KOF_DOCOLE_DIR_ENT)))))))
#define KOF_KID_FLOOR      4096u

static uint32_t kids_default(uint64_t obj_size)
{
	uint64_t k = obj_size / KOF_KID_RECORD_MIN;

	if (k < KOF_KID_FLOOR)
		k = KOF_KID_FLOOR;
	return k > 0xffffffffu ? 0xffffffffu : (uint32_t)k;
}

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
	sc->ledger.kids_left = opt->max_children ? opt->max_children : kids_default(obj_size);
	sc->ledger.window_left = kof_sat_add(obj_size, want);
	sc->ledger.emu_left = KOF_SCAN_EMU_MAX;
	sc->ledger.emu_insn_left = oc_emu_tree_insn(obj_size, opt->max_emu_insn);
	sc->ledger.emu_floor_left = KOF_SCAN_EMU_FLOOR_RUNS;
	sc->ledger.resident = 0;
	sc->ledger.names = 0;
	sc->ledger.names_max = KOF_SCAN_NAMES;
	sc->ledger.resident_max = opt->max_resident_bytes ? opt->max_resident_bytes
						   : (128ull << 20);
	/*
	 * SHARED OUT AMONG THE WORKERS OF A PARALLEL WALK, the given allowance or the
	 * built-in one alike (see kof_scan_option.resident_per_scanner), and floored.
	 */
	if (sc->share > 1u && !opt->resident_per_scanner) {
		sc->ledger.resident_max /= sc->share;
		if (sc->ledger.resident_max < KOF_SHARE_MIN)
			sc->ledger.resident_max = KOF_SHARE_MIN;
	}
	kof_scan_scratch(sc, opt);
	kof_scan_root_share(sc);
	/*
	 * Half the ceiling, at most.
	 *
	 * Not the whole of it: while a child is being unpacked, that child is itself
	 * resident, so a cap the size of the ceiling leaves no room to produce
	 * anything and the tree stops one level down. Half means the object in hand
	 * and the object being built both fit, which is what lets a container be
	 * unpacked one entry at a time. Less the record of the object in hand (oc_kid_cost): a
	 * collected child is charged its record as well as its bytes, so an entry cut AT the cap
	 * (tests/unit/budget.c, bomb-roomy: an 8 MB ceiling and 4 MB entries) must leave that
	 * much, or the second of the two is refused by a kilobyte and the tree stops after one.
	 */
	sc->ledger.obj_cap = opt->max_object_bytes ? opt->max_object_bytes : KOF_OBJ_CAP;
	{
		const uint64_t half = sc->ledger.resident_max / 2;
		const uint64_t room = half > oc_kid_cost() ? half - oc_kid_cost() : 0u;

		if (sc->ledger.obj_cap > room)
			sc->ledger.obj_cap = room;
	}
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
	sc->sink.cut = 0;
	sc->sink.refuse = 0;
}

/*
 * A bound that cut evidence of THIS object, said and counted.
 *
 * For a limit that exists against a hostile input and was met by one the engine
 * could still read the rest of (a parser's table, the rounds of a decode, a table
 * of a declaration): the object reads as incomplete - the verdict stage gives its
 * result KOF_BROKEN_LIMIT when nothing earlier explained it - and the scanner's
 * counter moves once for the object, so neither the verdict path nor a caller
 * reading the stats can take the answer for a complete one.
 *
 * It sets `cut` and not `broken`, on purpose: `broken` also ENDS the open stages
 * (an unpack loop stops on any value), and a bound that fires in the parse or the
 * normaliser must not stop the unpackers that would open what the table did hold.
 */
void oc_scan_limit_at(struct kof_scanner *sc, const char *file, int line)
{
	KOF_TRACE("[cut] %s:%d limit\n", file, line);
	(void)file; (void)line;
	if (!sc->obj.open.cut)
		sc->st.limit_hits++;
	sc->obj.open.cut = 1;
}
