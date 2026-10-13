/*
 * objctx_emu_gather.c - what a run produced, gathered into one image and the regions beside it: the
 * image builders, the written-memory pass and oc_emu_gather. Split from objctx_emu.c;
 * the text is unchanged.
 */

#define _GNU_SOURCE

#include "../kofcore/kofdebug.h"
#include "objctx_int.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <genotype/image/elf_rebuild.h>
#include "../analyzers/genome_obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * IS THIS IMAGE ANYTHING THE RUN ACTUALLY MADE?
 *
 * A stub copies itself before it unpacks - UPX maps its own file, relocates
 * into the copy and mprotects it executable - and that copy trips the same
 * "memory made executable" test the payload does. Measured over the malware
 * corpus: of 15 objects that reached the instruction ceiling, every single one
 * handed back exactly one image, and every one of those was the UPX stub,
 * recognisable by the strings it carries about /proc/self/exe. Those bytes are
 * already in the object, which is already being scanned, so a child made of
 * them can find nothing that was not going to be found anyway - and it puts a
 * node in the tree that a person then has to work out is not the payload.
 *
 * Decided by asking whether the content is ALREADY IN THE FILE, which is the
 * general form of the question and holds for any self-copying stub rather than
 * for UPX in particular. Three probes rather than one because a decompressed
 * payload can easily repeat one short run of the file it came from; all three
 * matching means this is a copy. Zero-filled probes are skipped - they say
 * nothing about origin - and an image with nothing but those is not worth
 * emitting either.
 *
 * The search is the engine's own, over the object's own match context, so this
 * costs what a signature costs and behaves the same way.
 */
#define NOVEL_PROBE  32u
#define NOVEL_TRIES  16u

/* An assembled image is worth a scan of its own when the run changed more than
 * one part in this many of what it started from. See where it is used. */
#define IMG_DIFF_DEN 64u

static int emu_novel(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	unsigned k, tried = 0, found = 0;

	if (n < NOVEL_PROBE)
		return 0;
	for (k = 1; k <= NOVEL_TRIES; k++) {
		uint64_t at = (n - NOVEL_PROBE) * k / (NOVEL_TRIES + 1u);
		unsigned j;

		for (j = 0; j < NOVEL_PROBE; j++)
			if (p[at + j])
				break;
		if (j == NOVEL_PROBE)
			continue;               /* all zeroes: says nothing */
		tried++;
		if (kof_match_in(&sc->match.m, 0, ctx->obj_size, p + at, NOVEL_PROBE,
				 KOF_CASE_EXACT, KOF_WORD_SUBSTRING))
			found++;
	}
	/*
	 * Nothing but zeroes is not a payload either.
	 *
	 * A MAJORITY rather than all of them, and that is the whole reason this
	 * is a proportion instead of a search. The stub's copy of itself is not
	 * byte-identical to the file - it relocates into the copy before it
	 * runs there - so asking whether any one run of bytes is present
	 * answered "new" for most probes and let all fifteen through. What
	 * separates the two cases is how MUCH of the image the file already
	 * contains: a relocated stub is nearly all of it, a decompressed
	 * payload is almost none.
	 */
	return tried && found * 2u < tried;
}

/* Read the emulated address space for the rebuilder, which knows nothing about
 * emulators and asks only for bytes at an address. */
static int emu_rd(void *user, uint64_t va, void *dst, uint32_t n)
{
	return kgenome_emu_read(user, va, dst, n);
}


/*
 * THE SAME PAGES, GATHERED TWICE.
 *
 * A guest may make one range executable more than once - PECompact's stub
 * mprotects its scratch area on every pass - and each call leaves a snapshot.
 * Two snapshots of the same address whose bytes are also the same are one fact
 * reported twice, and handing both over produced two sections with the same
 * name and the same content in the child: `.e020000` twice, 8192 bytes each,
 * on 007 Spy.exe.
 *
 * ONLY WHEN THE BYTES MATCH TOO. The same address with DIFFERENT content is two
 * facts - the page before a decode and after it - and dropping the second would
 * be dropping the result.
 *
 * Here and not in emu_harvest.h: this is the gathering saying the same thing
 * twice, not a module deciding what a page means.
 */
static int emu_dup(const struct emu_extra *ex, uint32_t n_ex, uint64_t va,
		   const uint8_t *p, uint64_t n)
{
	uint32_t i;

	for (i = 0; i < n_ex; i++)
		if (ex[i].va == va && ex[i].n == n &&
		    memcmp(ex[i].p, p, (size_t)n) == 0)
			return 1;
	return 0;
}

/*
 * What the gathering of one run holds from step to step: the one image the run
 * produced (if it did), the range of addresses that image accounts for, and the
 * extra regions collected beside it. Each step reads what the one before left.
 */
struct emu_gather {
	const uint8_t *img_p;
	uint64_t img_n, img_va;
	uint64_t built_lo, built_hi;
	struct emu_extra ex[EMU_EXTRA_MAX];
	uint32_t n_ex;
	int built, any;
};

/* The diagnostics of a stopped run, for a build that asked for them. */
static void emu_trace_stop(struct kgenome_emu *e,
			   const struct kgenome_emu_unp_report *rep)
{
	/*
	 * WHERE THE RUN STOPPED, ON REQUEST.
	 *
	 * emu.h says of the stop reasons that they "are the map of what to
	 * implement next", and until this existed there was no way to read the
	 * map: every one of them arrived in a struct that nothing printed, so a
	 * run that got nowhere and a run that got 48 million instructions in
	 * and stopped on one missing instruction looked identical from outside
	 * - both were "emu recovered nothing".
	 *
	 * Two of this engine's gaps were found with exactly this in one
	 * sitting: PUSHFQ, which four protected samples reached after 22 to 48
	 * million instructions of real work, and the thread block, which they
	 * reached immediately after.
	 *
	 * Off unless the build asked for it - see kofdebug.h.
	 */
	if (KOF_TRACING && e) {
		uint32_t xr = 0, xt = 0, xv = 0;

		uint64_t tr[256];
		unsigned nt, ti;

		kgenome_emu_exc_counts(e, &xr, &xt, &xv);
		if (KOF_TRACING) {
			unsigned mi;

			fprintf(stderr, "[emu] module reads:");
			for (mi = 0; mi < kgenome_emu_win_mod_count(); mi++)
				fprintf(stderr, " %s=%llu",
					kgenome_emu_win_mod_name(mi),
					(unsigned long long)
						kgenome_emu_mod_reads(e, mi));
			fprintf(stderr, "\n");
		}
		/*
		 * The registers at the stop. A VM's context pointer is a
		 * register, and "it read zero from [rbp+0x170]" means nothing
		 * until rbp is known - it decides whether the guest is reading
		 * a structure this environment failed to build or one it was
		 * pointed at by mistake.
		 */
		{
			static const char *const rn[16] = {
				"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
				"r8","r9","r10","r11","r12","r13","r14","r15"
			};
			unsigned ri;

			fprintf(stderr, "[emu] regs:");
			for (ri = 0; ri < 16u; ri++)
				fprintf(stderr, "%s %s=%#llx",
					(ri % 4u) ? "" : "\n     ", rn[ri],
					(unsigned long long)
						kgenome_emu_get_reg(e, ri));
			fprintf(stderr, "\n");
		}
		{
			uint64_t hi2 = 0, hr = 0;

			kgenome_emu_first_hop(e, &hi2, &hr);
			fprintf(stderr, "[emu] first hop at insn=%llu rip=%#llx\n",
				(unsigned long long)hi2,
				(unsigned long long)hr);
		}
		nt = kgenome_emu_trace(e, tr, 256u);
		fprintf(stderr, "[emu] last rips:");
		for (ti = 0; ti < nt; ti++)
			fprintf(stderr, " %#llx", (unsigned long long)tr[ti]);
		fprintf(stderr, "\n");
		fprintf(stderr, "[emu] exc raised=%u taken=%u veh=%u "
			"null-calls=%u unhandled=%u\n", xr, xt, xv,
			kgenome_emu_null_calls(e), kgenome_emu_unhandled(e));
		fprintf(stderr, "[emu] null-reads=%u idle-max=%llu decrypt=%d\n",
			kgenome_emu_null_reads(e),
			(unsigned long long)kgenome_emu_idle_max(e),
			kgenome_emu_write_seen(e));
	}
	/* A diagnostic: a build choice, like the block above - see CLAUDE.md 1. */
	if (KOF_TRACING && e && kgenome_emu_itrace_count(e)) {
		static const char *const rn[16] = {
			"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
			"r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
		};
		unsigned have = kgenome_emu_itrace_count(e), k, g;

		for (k = 0; k < have; k++) {
			uint64_t at = 0;
			const char *tx = NULL;
			const uint64_t *gp = NULL;

			if (!kgenome_emu_itrace_get(e, k, &at, &tx, &gp))
				break;
			fprintf(stderr, "[ins] %#018llx  %-40s",
				(unsigned long long)at, tx ? tx : "");
			for (g = 0; g < 16u; g++)
				fprintf(stderr, " %s=%llx", rn[g],
					(unsigned long long)(gp ? gp[g] : 0));
			fprintf(stderr, "\n");
		}
	}
	KOF_TRACE("[emu] why=%d stop=%d insn=%llu entry=%#llx "
			"images=%u written=%u returned=%d improvised=%d "
			"detail=%s refused=%s\n",
			(int)rep->why, (int)rep->stop,
			(unsigned long long)rep->insn,
			(unsigned long long)rep->entry, rep->images, rep->written,
			rep->returned, rep->improvised,
			rep->detail ? rep->detail : "-",
			rep->refused ? rep->refused : "-");
}

/*
 * The whole PE image, when the run put the sections back where they belong and
 * changed enough of them to be worth handing over.
 */
static void emu_gather_pe_image(const struct kof_obj_ctx *ctx,
				struct kof_scanner *sc, struct kgenome_emu *e,
				kof_buf b, struct emu_gather *g)
{
	uint8_t *whole = NULL;
	uint64_t wlen = 0;
	const struct kgenome_pe_info *pi = kof_pe(ctx);

	int ok = pi && pi->valid &&
		 kgenome_emu_unp_pe_image(e, pi, pi->image_base,
				       sc->ledger.obj_cap, &whole, &wlen);

	if (ok) {
		/*
		 * THE TEST FOR THIS PRODUCT IS "DID THE RUN CHANGE IT",
		 * NOT "IS IT NEW".
		 *
		 * emu_novel asks whether a majority of an image is
		 * already in the parent, which is the right question
		 * about a region a stub mapped - a relocated copy of
		 * itself is nearly all parent, a decompressed payload
		 * is almost none. It is the WRONG question about this
		 * one: an image decrypted in place IS the parent
		 * everywhere the packer left alone. Measured on an
		 * MPRESS sample, 1.2 MB of ciphertext inside 8 MB of
		 * ordinary code - so fourteen of fifteen probes hit and
		 * the decrypted image was thrown away.
		 *
		 * What separates a run that produced something from one
		 * that did not is whether it WROTE inside the image.
		 * The stack and the host's exception scratch are not
		 * the image and are excluded by range, exactly as the
		 * written-memory harvest below excludes them.
		 */
		uint64_t diff = 0, seen = 0;
		uint32_t si;
		int changed;

		/*
		 * HOW MUCH, counted against the file this run started
		 * from, section by section - raw offset in the file
		 * against virtual address in the image, which is the
		 * only pairing that means anything.
		 *
		 * Measured, the threshold is the whole point. An MPRESS
		 * run changes 2112 bytes of an 8245248 byte image and a
		 * Themida one 2565 of 5910528 - import thunks and a few
		 * patched sites - so handing the image over costs eight
		 * megabytes of scan for two kilobytes of new content,
		 * and the same rules run over the same bytes twice. A
		 * loader that actually decrypted its sections changes
		 * them by percent, not by thousandths.
		 */
		for (si = 0; si < pi->sec_count &&
			     si < KGENOME_PE_MAX_SECTIONS; si++) {
			const struct kgenome_pe_sec *ps = &pi->sec[si];
			uint64_t n = ps->file_size, q;

			if (!n || ps->file_off >= b.n ||
			    ps->mem_rva >= wlen)
				continue;
			if (n > b.n - ps->file_off)
				n = b.n - ps->file_off;
			if (n > wlen - ps->mem_rva)
				n = wlen - ps->mem_rva;
			seen += n;
			for (q = 0; q < n; q++)
				if (b.p[ps->file_off + q] !=
				    whole[ps->mem_rva + q])
					diff++;
		}
		changed = seen && diff * IMG_DIFF_DEN > seen;
		KOF_TRACE("[img] len=%llu diff=%llu/%llu "
				"changed=%d\n",
				(unsigned long long)wlen,
				(unsigned long long)diff,
				(unsigned long long)seen, changed);
		if (changed) {
			/* Recorded, not handed over: what this is, is
			 * the unpack module's to say. The buffer is
			 * the engine's and is held until the module
			 * that asked for the run returns. */
			free(sc->emu.own);
			sc->emu.own = whole;
			g->img_p = whole;
			g->img_n = wlen;
			g->img_va = pi->image_base;
			whole = NULL;
			g->built = 1;
			/*
			 * AND THE REGIONS IT ACCOUNTS FOR ARE SPENT.
			 * Every section of the assembled file lies in
			 * [base, base + SizeOfImage), so that range is
			 * what the snapshot loop below must skip -
			 * otherwise the same bytes are handed over
			 * twice, once as a file with a section table
			 * and once as a formatless region. Measured on
			 * a PECompact2 sample: 14.81 MB against 8.66,
			 * the difference being its .text a second
			 * time. Allocations the run made elsewhere are
			 * outside the range and still come back.
			 */
			g->built_lo = pi->image_base;
			g->built_hi = pi->image_base + g->img_n;
		}
		free(whole);
	}
}

/*
 * The first snapshot that is a program: an ELF rebuilt into a file, or a PE the
 * run built in one region. One per run.
 */
static void emu_gather_header_image(const struct kof_obj_ctx *ctx,
				    struct kof_scanner *sc, struct kgenome_emu *e,
				    int is_pe, struct emu_gather *g)
{
	uint32_t it;
	uint64_t va, len;
	const uint8_t *bytes;

	for (it = 0; kgenome_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		uint8_t *file = NULL;
		uint64_t flen = 0;

		if (is_pe) {
			/*
			 * THE PE HALF REBUILDS FROM THE REGION, not through a
			 * reader, and the difference is not a shortcut.
			 *
			 * kgenome_elf_rebuild walks a guest's segments by
			 * ADDRESS because an ELF image is several mappings
			 * that a stub placed itself - it has to be able to
			 * reach across them. A PE that a stub built is one
			 * contiguous image at one base, because that is the
			 * only shape the Windows loader takes and a packer
			 * reproducing it has no reason to scatter it. So the
			 * region IS the image, and kof_pe_rebuild - which
			 * already serves the in-memory path above - takes it
			 * as it stands.
			 *
			 * An image genuinely spread over several regions is
			 * not rebuilt and falls through to being handed over
			 * as raw bytes, which is what happened to every
			 * snapshot before any of this existed.
			 */
			if (len < 2 || bytes[0] != 'M' || bytes[1] != 'Z')
				continue;
			/*
			 * DECLARED, NOT REBUILT INTO A SECOND BUFFER.
			 *
			 * kof_pe_rebuild used to be called here: it hunted for
			 * the header, allocated an image-sized buffer and
			 * copied every section into it so the engine could
			 * parse the result back. The run already put those
			 * bytes at their addresses - the region IS the image -
			 * so the copy recovered nothing that was not already
			 * there.
			 *
			 * Now the region is taken as the child and the layout
			 * is read out of the header inside it. Same source,
			 * one buffer, and the sections arrive with an origin
			 * that says a run recovered them.
			 */
			if (!emu_novel(ctx, bytes, len))
				continue;
			g->img_p = bytes;
			g->img_n = len;
			g->img_va = va;
			g->built = 1;
			g->built_lo = va;
			g->built_hi = va + len;
			break;
		} else {
			if (len < 4 || memcmp(bytes, "\177ELF", 4))
				continue;
			if (!kgenome_elf_rebuild(va, emu_rd, e, sc->ledger.obj_cap,
					     &file, &flen, &g->built_lo,
					     &g->built_hi))
				continue;
		}
		/*
		 * `built` MEANS A CHILD WAS PRODUCED, not that a header was
		 * found.
		 *
		 * It is what `any` starts from, and `any` is what decides
		 * whether the written-memory fallback runs at all. Set here
		 * unconditionally, a rebuild whose image emu_novel then
		 * recognised as the stub's own copy of itself produced NOTHING
		 * and still turned the fallback off - so a stub that maps a
		 * copy of its own file, decrypts its payload into ordinary
		 * written memory and never calls mprotect on it came back with
		 * no children at all, and the reason was the copy.
		 *
		 * built_lo/built_hi are still set either way, and must be:
		 * they keep the snapshot loop below from handing those same
		 * bytes over raw. That is a different question from whether
		 * anything was produced.
		 */
		if (emu_novel(ctx, file, flen)) {
			free(sc->emu.own);
			sc->emu.own = file;
			g->img_p = file;
			g->img_n = flen;
			g->img_va = va;
			file = NULL;
			g->built = 1;
		}
		free(file);
		break;                  /* one program per run is what a stub
					 * produces; a second header found in
					 * its data is not a second program */
	}
}

/* The memory the run made executable, collected beside the image. */
static void emu_gather_exec_snapshots(const struct kof_obj_ctx *ctx,
				      struct kof_scanner *sc,
				      struct kgenome_emu *e, struct emu_gather *g)
{
	uint32_t it;
	uint64_t va, len;
	const uint8_t *bytes;

	/*
	 * Snapshots first, and the written pages only if there were none.
	 *
	 * A snapshot is memory a program made executable, which is a payload
	 * saying so about itself; written memory is everything else it touched,
	 * stack and scratch included. When both exist the snapshots ARE the
	 * result and the rest is noise - measured on a UPX-packed PyInstaller
	 * binary, the written set held the payload plus twelve kilobytes of
	 * stub and stack, and the payload had since been overwritten in place.
	 * When a packer never calls mprotect there are no snapshots, and then
	 * the written pages are all there is.
	 */
	for (g->any = g->built, it = 0;
	     kgenome_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		if (va >= g->built_lo && va < g->built_hi)
			continue;               /* already in the rebuilt file */
		if (!emu_novel(ctx, bytes, len))
			continue;               /* the stub's own copy of itself */
		g->any = 1;
		/* Memory the run made executable, or wrote and then ran - see
		 * the write-then-execute snapshot in emu_interp.c. Collected rather
		 * than handed over: it belongs to the same program as the
		 * image, and emu_one_child puts them together. */
		if (g->n_ex < EMU_EXTRA_MAX && !emu_dup(g->ex, g->n_ex, va, bytes, len)) {
			g->ex[g->n_ex].p = bytes;
			g->ex[g->n_ex].own = NULL;   /* a snapshot lives in the
						* machine, which outlives the
						* module - see emu_rgn */
			g->ex[g->n_ex].n = len;
			g->ex[g->n_ex].va = va;
			g->ex[g->n_ex].code = 1;
			g->n_ex++;
		} else if (g->n_ex >= EMU_EXTRA_MAX &&
			   !emu_dup(g->ex, g->n_ex, va, bytes, len)) {
			/* A bound on what one run may hand over. It stays a bound,
			 * and it SAYS it was reached: dropped without a word, a
			 * region past the thirty-second was evidence that simply
			 * was not there. */
			oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		}
	}
}

/*
 * The written-memory fallback: what a finished run wrote, when nothing was
 * made executable.
 */
static void emu_gather_written(const struct kof_obj_ctx *ctx,
			       struct kof_scanner *sc, struct kgenome_emu *e,
			       const struct kgenome_emu_unp_report *rep,
			       struct emu_gather *g)
{
	uint32_t it;
	uint64_t va, len;
	const uint8_t *bytes;

	/*
	 * The written-memory fallback needs the run to have FINISHED.
	 *
	 * A snapshot is a packer saying "this is code now" about its own
	 * output, so it is a payload whenever it exists. Written memory is not:
	 * it is everything the guest touched, stack and scratch included, and
	 * it is only the whole of what was produced once the guest has stopped
	 * on its own terms. Measured over the malware corpus - of 17 objects no
	 * static unpacker opened, 2 ran to their own exit and yielded an 86 KB
	 * ELF each, and the other 15 hit the instruction ceiling and yielded
	 * four to twelve kilobytes of stub and stack. Handing those back cost a
	 * scan 15 child objects that were not payloads and could not be.
	 *
	 * A STALL COUNTS AS FINISHED, and that is not the same concession.
	 *
	 * Hitting the ceiling says the budget ran out, which says nothing about
	 * whether the guest was still producing. A stall is the opposite
	 * statement: no page has been written for four million instructions, so
	 * whatever this run was going to write, it already has. The case that
	 * needs it is self-decrypting shellcode, which decrypts a buffer and
	 * then enters a loop that never returns - a listener, a connect retry -
	 * so it never exits and never hands off. Measured on a stub that
	 * decrypts two kilobytes and then spins: without this the plaintext sits
	 * in the emulator's written set and is thrown away, with it the payload
	 * comes back. Measured over the malware corpus the two settings are
	 * indistinguishable - 308 objects, 60 infected, 19 suspected either way
	 * - so nothing in that collection stalls with unharvested memory, and
	 * the clean corpus gains no findings.
	 */
	/*
	 * AND A PE STUB THAT RETURNED, which is the fourth way to finish and
	 * the only one that had no entry in this list.
	 *
	 * The three stops above are how an ELF stub ends: it exits, it hands
	 * off, or it stalls. A PE entry point is CALLED by the loader, so the
	 * ordinary ending for one is `ret` - and that arrives here as a fault,
	 * because the return address the run was given points at nothing on
	 * purpose. Without this the most normal successful PE run in existence
	 * was classified with "ran off into nothing" and had its output thrown
	 * away; measured on a stub that decodes a buffer and returns, the
	 * plaintext was in the written set and never handed over.
	 *
	 * It is `rep.returned` and not `stop == FAULT`, so this stays a
	 * statement about one specific address rather than an amnesty for
	 * every run that went somewhere it should not have.
	 */
	/*
	 * AND A RUN THAT SPENT ITS BUDGET, which this used to refuse.
	 *
	 * The reasoning above is that hitting the ceiling "says the budget ran
	 * out, which says nothing about whether the guest was still producing",
	 * and that a short run's written set is stub and stack rather than
	 * payload. Both halves were measured on runs that reached the ceiling
	 * in a few thousand instructions.
	 *
	 * A run that reaches it after a HUNDRED AND SIXTY MILLION is a
	 * different object. Measured on a PECompact2 sample: 168,558,592
	 * instructions, eight regions of written memory, and every one of them
	 * discarded - thirteen seconds spent to throw away whatever eight
	 * megabytes of decompression had got to. Nothing about "the budget ran
	 * out" makes those bytes less real.
	 *
	 * emu_novel is what keeps this honest, and it is the same filter the
	 * other three reasons rely on: a region that is the stub's own copy of
	 * itself is dropped, and so is the stack, by range. What survives is
	 * memory this run built.
	 */
	/*
	 * STILL ONLY WHEN THERE WERE NO SNAPSHOTS, and an experiment says so.
	 *
	 * Relaxing this to "or the run reached ExitProcess" looked right - a
	 * program that ran to its own exit has its memory in the written set,
	 * not in two pages of scratch - and measured it reproduced exactly the
	 * failure this rule exists to prevent: a 329 KB PECompact2 sample came
	 * back as 30 objects and 140.40 MB, against 6 and 8.62 MB. What that
	 * sample needed was never the written set; it was the write-then-
	 * execute snapshot, which goes through the loop above and is not
	 * gated here at all.
	 */
	if (!g->any && (rep->stop == KGENOME_EMU_STOP_EXIT ||
		     rep->stop == KGENOME_EMU_STOP_HANDOFF ||
		     rep->stop == KGENOME_EMU_STOP_STALLED ||
		     rep->stop == KGENOME_EMU_STOP_BUDGET ||
		     rep->returned))
		for (it = 0; kgenome_emu_next_written(e, &it, &va, &bytes, &len); ) {
			if (va >= g->built_lo && va < g->built_hi)
				continue;
			/* What the stub pushed is not what it unpacked. See
			 * kgenome_emu_unp_report.stack_lo. */
			if (rep->stack_hi && va >= rep->stack_lo &&
			    va < rep->stack_hi)
				continue;
			/* Nor the exception records, which the HOST wrote. */
			if (rep->exc_hi && va >= rep->exc_lo && va < rep->exc_hi)
				continue;
			if (!emu_novel(ctx, bytes, len))
				continue;
			if (g->n_ex < EMU_EXTRA_MAX &&
			    !emu_dup(g->ex, g->n_ex, va, bytes, len)) {
				/*
				 * COPIED, BECAUSE THIS ONE IS BORROWED. See
				 * kgenome_emu_next_written: the buffer it answers
				 * with is replaced on the next call, so every
				 * region but the last would be freed before
				 * the module that asked for them ran.
				 */
				uint8_t *own = malloc((size_t)len);

				if (!own)
					break;
				memcpy(own, bytes, (size_t)len);
				g->ex[g->n_ex].p = own;
				g->ex[g->n_ex].own = own;
				g->ex[g->n_ex].n = len;
				g->ex[g->n_ex].va = va;
				g->ex[g->n_ex].code = 0;
				g->n_ex++;
			} else if (g->n_ex >= EMU_EXTRA_MAX &&
				   !emu_dup(g->ex, g->n_ex, va, bytes, len)) {
				oc_scan_capped(sc, KOF_BROKEN_LIMIT);     /* said, not dropped */
			}
		}
}

/* The scanner's region table, from the image and the extras. */
static void emu_gather_regions(struct kof_scanner *sc,
			       const struct emu_gather *g)
{
	/*
	 * AND THAT IS ALL A RUN DOES: it says what it found.
	 *
	 * No child is made here and none ever should be. The interpreter is
	 * the one component that executes hostile bytes, and giving it the
	 * power to create objects as well made the widest surface in the engine
	 * wider still. It gathers; a module reads the gathering and decides
	 * what any of it is; the engine builds what the module declares. See
	 * kof_scan_emu_region and oc_emu_take.
	 *
	 * The regions point into the machine's own memory, so the machine stays
	 * alive until the module that asked for the run has returned - see
	 * kof_scan_emu_release.
	 */
	sc->emu.n_rgn = 0;
	if (g->img_p && sc->emu.n_rgn < KOF_EMU_RGN_MAX) {
		sc->emu.rgn[sc->emu.n_rgn].p = g->img_p;
		/* img_p is sc->emu.own, freed with it. */
		sc->emu.rgn[sc->emu.n_rgn].own = NULL;
		sc->emu.rgn[sc->emu.n_rgn].va = g->img_va;
		sc->emu.rgn[sc->emu.n_rgn].n = g->img_n;
		sc->emu.rgn[sc->emu.n_rgn].kind = KOF_EMU_RGN_IMAGE;
		sc->emu.n_rgn++;
	}
	{
		uint32_t q;

		for (q = 0; q < g->n_ex && sc->emu.n_rgn < KOF_EMU_RGN_MAX; q++) {
			sc->emu.rgn[sc->emu.n_rgn].p = g->ex[q].p;
			sc->emu.rgn[sc->emu.n_rgn].own = g->ex[q].own;
			sc->emu.rgn[sc->emu.n_rgn].va = g->ex[q].va;
			sc->emu.rgn[sc->emu.n_rgn].n = g->ex[q].n;
			sc->emu.rgn[sc->emu.n_rgn].kind = g->ex[q].code
				? KOF_EMU_RGN_EXEC : KOF_EMU_RGN_WRITTEN;
			sc->emu.n_rgn++;
		}
	}
	if (KOF_TRACING) {
		uint32_t q;

		for (q = 0; q < sc->emu.n_rgn; q++)
			fprintf(stderr,
				"[emu] rgn %u va=0x%llx len=%llu kind=%u\n", q,
				(unsigned long long)sc->emu.rgn[q].va,
				(unsigned long long)sc->emu.rgn[q].n,
				sc->emu.rgn[q].kind);
	}
}

/*
 * WHAT A RUN LEFT, TURNED INTO REGIONS - the half of kof_scan_emu_unpack that
 * happens AFTER the machine stops.
 *
 * Split out so that a PAUSED run can be resumed and gathered by the same code.
 * A module that named an instruction to stop on - see kgenome_emu_watch_insn - gets
 * control back with the machine intact, reads what it wanted, and asks for the
 * run to continue; when it finally stops for good, what it left is gathered
 * here exactly as it would have been without the pause. Two copies of this
 * would be two answers to "what did the run produce".
 */
uint32_t oc_emu_gather(const struct kof_obj_ctx *ctx,
			   struct kof_scanner *sc, struct kgenome_emu *e,
			   struct kgenome_emu_unp_report rep)
{
	struct emu_gather g;
	kof_buf b;
	int is_pe;

	g.img_p = NULL;
	g.img_n = 0;
	g.img_va = 0;
	g.built_lo = ~0ull;
	g.built_hi = 0;
	g.n_ex = 0;
	g.built = 0;
	g.any = 0;

	is_pe = ctx->format == KOF_FMT_PE;
	b = kof_src_buf(sc->cur.src);
	emu_trace_stop(e, &rep);
	if (!e) {
		/*
		 * No image could be built, and the reasons are all statements
		 * about the object: its entry point is past the bytes it
		 * actually holds, or it declares none. Recorded on the same
		 * channel a container uses for a truncated entry, so the object
		 * reads as "not fully examined, and here is why" rather than as
		 * one nothing happened to. A truncated UPX sample looks exactly
		 * like this - the stub sits past the compressed data, so the
		 * part that is missing is the part that would have run.
		 */
		if (rep.refused)
			oc_scan_broken(sc, KOF_BROKEN_DAMAGED);
		return 1;               /* tried, and said why it could not */
	}

	/*
	 * AN IMAGE IS NOT A FILE, AND A SCANNER WANTS THE FILE.
	 *
	 * What a run leaves is segments at their virtual addresses, spread over
	 * however many regions the guest mapped. Handed over as they are, the
	 * one holding the ELF header identifies as ELF with no sections - they
	 * are in a different region - and the rest identify as nothing, so no
	 * region partition exists and no signature scoped to CODE or DATA can
	 * run on any of it. Measured on a sample this unpacks correctly: six
	 * regions, five of them formatless, against a static unpacker's single
	 * 2.8 MB file that partitions into HEADERS, CODE, DATA and NOLOAD.
	 *
	 * So a region that starts with an ELF header is rebuilt into a file
	 * first, and the addresses that file accounts for are then skipped -
	 * emitting them again would hand the same bytes over twice, once with
	 * structure and once without.
	 */
	/*
	 * THE WHOLE IMAGE FIRST, when the run put sections back where they
	 * belong. See kgenome_emu_unp_pe_image: a region that starts exactly at a
	 * section's address is that section, and the allocations, the thread
	 * block, the stack and the host's own scratch are not. Assembled into
	 * one file with the parent's header, so what comes out identifies as a
	 * PE and gets regions, imports and every rule scoped to them.
	 *
	 * Before the loop below and not instead of it: a run that put nothing
	 * at a section address falls through to the old behaviour unchanged.
	 */
	if (is_pe)
		emu_gather_pe_image(ctx, sc, e, b, &g);
	emu_gather_header_image(ctx, sc, e, is_pe, &g);

	emu_gather_exec_snapshots(ctx, sc, e, &g);
	emu_gather_written(ctx, sc, e, &rep, &g);

	emu_gather_regions(sc, &g);

	/*
	 * A BUDGET STOP IS NOT REPORTED AS A LIMIT, and that is a departure
	 * from what a decompressor does on the same event.
	 *
	 * For a decompressor the two coincide: hitting the ceiling means bytes
	 * were left unproduced, so "not fully examined" is exactly true. Here
	 * they do not. A stub writes its payload and then spends instructions
	 * on things that produce nothing more - relocating itself, running the
	 * program it unpacked - so stopping late usually costs nothing at all.
	 * Measured over 200 UPX-packed binaries: 21 reached the ceiling and
	 * every one of them had already recovered its payload byte for byte.
	 *
	 * Marking those "not fully examined" put 13 objects of a 215-file
	 * corpus under a heading that means "look again", where looking again
	 * would have found the same thing. The flag is worth more kept for the
	 * case it is true of.
	 */
	/* KEPT, not freed: the regions above point into it. */
	sc->emu.live = e;
	sc->emu.paused = 0;
	return sc->emu.n_rgn;
}
