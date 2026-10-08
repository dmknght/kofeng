/*
 * objctx_emu.c - the interpreter a module asks the engine to drive.
 *
 * WHAT THIS SERVES: an unpacker or a heuristic that wants a program RUN - to
 * decrypt itself, to reveal what it calls - asks the engine, because only the
 * engine owns the budget, the memory ceiling and the machine that outlives the
 * module call. This unit builds the run (kof_scan_emu_unpack), gathers what it
 * produced into regions, and answers the module's questions about the machine
 * (registers, memory, resume, take).
 *
 * OPEN, with what was measured so it is not re-derived:
 *  - the PE image-diff filter (IMG_DIFF_DEN) and the written-memory fallback
 *    (`any = built`, the stop-reason list) are family policy that belongs in a
 *    declared driver. On pe300, 27 image builds: 18 identical to the parent (the
 *    drop is exact), 9 changed 64..61043 bytes, none past the filter. Handing
 *    over only the changed spans was tried: +6 objects and the parent's
 *    Heur:WriteExec on pe300/005 vanished, because scan.c drops a parent's
 *    heuristic findings whenever it has a produced child (n_kids > n_views +
 *    n_carved) and a formatless region says nothing. Fix that rule first.
 *  - EMU_IDLE_DECLARED and EMU_INSN_PER_BYTE carry MPRESS/Themida/UPX numbers in
 *    generic constants.
 */

/* Before any include, and _GNU_SOURCE rather than _POSIX_C_SOURCE, for the
 * reason dbloader.c gives at length: kofplatform.h's POSIX branch has an inline
 * kof_memmem whose body calls memmem, which glibc declares only under this
 * macro - and _POSIX_C_SOURCE actively suppresses it. */
#define _GNU_SOURCE

#include <kofmod/kofsym.h>
#include <kofmod/heur.h>   /* KOF_ENG_USE_EMU - a module's declaration */
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "../analyzers/parsers/binaries/elf/elf_sym.h"
#include <kofmod/kofpathogen.h>
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include <celllysis/xref.h>
#include "../disinfect/pzero.h"
#include "../analyzers/normalize/executables.h"
#include "scan.h"
#include "objctx_int.h"
#include <kofmod/elf.h>
#include "../extractors/unpack/emu_unpack.h"
#include "../extractors/unpack/elf_rebuild.h"

#include "../extractors/decomp/ovba.h"
#include "../extractors/decomp/lzma.h"
#include "../extractors/decomp/aplib.h"
#include "../extractors/decomp/aspack.h"
#include "../extractors/decomp/lzmat.h"
#include "../extractors/decomp/bcj.h"
#include "../extractors/decomp/rar3.h"
#include "../extractors/decomp/rar5.h"
#include "../extractors/decomp/bcj2.h"
/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_fold below. */
#include "../analyzers/parsers/scripts/script_norm.h"
#include "../analyzers/parsers/scripts/script_parse.h"
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */
#include <kofmod/sevenzip.h>

#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/pathogen/kofdiag.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "objctx_int.h"

/* ---- the last resort ------------------------------------------------------
 *
 * See kof_scan_emu_unpack in scan.h.
 */

/*
 * THE INSTRUCTION BUDGET, DERIVED FROM THE OBJECT RATHER THAN CHOSEN.
 *
 * A fixed five million was the single thing most wrong with this stage, and it
 * did not look wrong: runs ended tidily at the ceiling having written
 * something, so they read as "the emulator got partway" when they were "the
 * emulator was interrupted mid-decompression". Measured over the seventeen
 * objects in the malware corpus that no unpacker could open, the work is
 * proportional to the PACKED SIZE and the constant is remarkably steady:
 *
 *     NRV (UPX method 14)          ~57 instructions per input byte
 *     LZMA (UPX method 14 + LZMA)  ~250-330 instructions per input byte
 *
 * and the totals ran from 2.7 million to 253 million. At five million, two of
 * the seventeen finished; with the budget below, fifteen do - the same code,
 * the same design, a ceiling that was two orders of magnitude under what
 * decompression costs.
 *
 * 512 per byte leaves headroom over the worst measured ratio. The floor keeps a
 * tiny object from getting a budget too small to leave its own entry code; the
 * cap is what a caller who asked for --heur 2 can be expected to tolerate on
 * one object, at the ten million instructions a second this interprets.
 */
#define EMU_INSN_PER_BYTE  512ull
#define EMU_INSN_MIN       (16ull << 20)
#define EMU_INSN_MAX       (256ull << 20)

/* The stall ceiling for a child a module asked to have run - see the call. */
#define EMU_IDLE_DECLARED  (128ull << 20)

static uint64_t emu_insn(uint64_t obj_size)
{
	/* Saturating, like the budget's own ratio a few functions up: the
	 * operand is a file size and the product is not checked anywhere
	 * after this. Wrapping would floor the budget instead of capping it,
	 * which is a run that fails for a reason nobody could read off the
	 * size. */
	uint64_t n = obj_size > UINT64_MAX / EMU_INSN_PER_BYTE
		   ? UINT64_MAX : obj_size * EMU_INSN_PER_BYTE;

	if (n < EMU_INSN_MIN)
		n = EMU_INSN_MIN;
	if (n > EMU_INSN_MAX)
		n = EMU_INSN_MAX;
	return n;
}

/*
 * THE INTERPRETER'S SHARE OF THE SCAN'S OWN MEMORY CEILING.
 *
 * Not a constant of its own. A caller who set max_resident_bytes did so to
 * bound what this scan holds at any instant, and an interpreter allocating
 * outside that number would make the setting a lie - it would be the one part
 * of the engine that ignored it. So the guest's address space comes out of what
 * is left under that ceiling, halved so that producing the payload afterwards
 * still has room: the images are copied into the sink while the emulator is
 * still holding its pages, and both live at once.
 *
 * Floored, because below a few megabytes nothing unpacks and the run would only
 * waste the instructions it takes to fail; capped, because a caller who allowed
 * a gigabyte did not thereby ask for a gigabyte of emulated address space.
 */
#define EMU_PAGES_MIN   (4u << 20)
#define EMU_PAGES_MAX   (128u << 20)

static uint64_t emu_pages(const struct kof_scanner *sc)
{
	uint64_t room = oc_scan_room(sc) / 2u;

	if (room > EMU_PAGES_MAX)
		room = EMU_PAGES_MAX;
	if (room < EMU_PAGES_MIN)
		room = EMU_PAGES_MIN;
	return room / KOF_EMU_PAGE;
}

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
		if (kof_match_in(&sc->m, 0, ctx->obj_size, p + at, NOVEL_PROBE,
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
	return kof_emu_read(user, va, dst, n);
}

/*
 * Hand one recovered image to the sink. Emitted in pieces because oc_emit takes
 * a uint32 length and refuses anything over EMIT_MAX - a decompressor already
 * works a window at a time and so does this.
 */
/*
 * ---- ONE OBJECT OUT OF A RUN, NOT A HANDFUL --------------------------------
 *
 * A run leaves two kinds of thing behind: the IMAGE a stub assembled, and
 * SURPLUS - pages it decompressed into the heap, made executable, or simply
 * wrote. Handing each one over separately is what produced the rows of
 * anonymous blobs beside the file: `emu:image@0x400000`, `emu:exec@0x20002000`,
 * `emu:written@...`, each re-parsed from nothing by whoever looked at it.
 *
 * They are one program. So the image is reconstructed and the surplus is folded
 * into it as EXTRA SECTIONS past its end - each keeping the guest address it
 * was lifted from, in its name, because that is the only thing tying it back to
 * where the run put it. One child, one section table, one thing to look at.
 *
 * AND WHEN THERE IS NO IMAGE, THE SURPLUS IS STILL WORTH HAVING. A stub that
 * never assembles a PE - a shellcode decoder, a packer that runs its payload
 * from the heap - leaves only surplus, and that is then the result rather than
 * a leftover. It goes out raw, one child per region, which is what this did for
 * everything before the reconstruction existed.
 */
#define EMU_EXTRA_MAX 32u

struct emu_extra {
	const uint8_t *p;
	/* Set when `p` is a copy this function made - see the note in
	 * kof_scanner.emu_rgn. It is handed to the scanner with the region and
	 * freed with it. */
	uint8_t       *own;
	uint64_t       n, va;
	int            code;
};

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

int oc_emit_exact(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n)
{
	return oc_emit_all(ctx, p, n) == n;
}


uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_emu_unp_report rep;
	struct kof_emu *e;
	kof_buf b;
	int is_pe;

	if (!sc || !sc->cur_src || !ctx->file_header)
		return 0;
	/*
	 * TWO FORMATS NOW, and the PE half arrived long after the ELF one.
	 *
	 * This read `ctx->format != KOF_FMT_ELF`, which was right when the
	 * bridge could only build an ELF process image. emu_unpack.h carries
	 * the argument for running a PE with no Windows API behind it; what
	 * matters here is that the two are the same shape from this side - a
	 * gate, a run, and a set of written pages to harvest - so the only
	 * thing that forks is which pair is called.
	 */
	if (ctx->format != KOF_FMT_ELF && ctx->format != KOF_FMT_PE)
		return 0;
	if (!oc_can_produce(sc))
		return 0;
	is_pe = ctx->format == KOF_FMT_PE;
	b = kof_src_buf(sc->cur_src);
	if (is_pe) {
		const struct kof_pe_info *info = kof_pe(ctx);

		if (!force && kof_emu_unp_gate_pe(ctx, info, b.p, b.n) ==
			      KOF_EMU_UNP_NO)
			return 0;
		{
			struct kof_emu_oep oep[KOF_EMU_EXEC_WATCH];
			unsigned k;

			for (k = 0; k < sc->n_xw; k++) {
				oep[k].rva = sc->xw[k].rva;
				oep[k].len = sc->xw[k].len;
			}
			KOF_TRACE("[emu] oep ranges=%u\n", sc->n_xw);
			{
				/* See emu_nolimit_ms in emu_unpack.c: the
				 * experiment switch, which replaces every work
				 * bound with a wall clock. 2 GB of guest pages
				 * is what "bounded by RAM" means here. */
				uint64_t bi = emu_insn(b.n), bp = emu_pages(sc);
				uint64_t idle = 0;

				/*
				 * AND A SLICE, WHEN THE MODULE ASKED FOR ONE -
				 * see `emu_slice`. The real ceiling is kept so
				 * that a stop at the slice can be told from a
				 * stop at the budget, which are opposite
				 * answers: one means "look and carry on", the
				 * other means "this is all there will be".
				 */
				sc->emu_full = bi;
				if (sc->emu_slice && sc->emu_slice < bi)
					bi = sc->emu_slice;
				KOF_TRACE("[emu] budget full=%llu slice=%llu use=%llu\n",
						(unsigned long long)sc->emu_full,
						(unsigned long long)sc->emu_slice,
						(unsigned long long)bi);

				/*
				 * A MODULE THAT ASKED FOR THE INTERPRETER GETS
				 * A LONGER LEASH, and only it does.
				 *
				 * The stall ceiling ends a run that has not
				 * touched a new page for four million
				 * instructions, which is the right answer for
				 * an object nothing recognised: a decoder fed
				 * junk spins to the budget and costs the scan
				 * every second of it. It is the wrong answer
				 * for a child a packer module produced and
				 * declared it wants run - measured, an MPRESS
				 * child computes for 84623471 instructions
				 * without a new page and then decrypts strings
				 * that are in neither the packed file nor the
				 * static unpacker's output, and a Themida one
				 * needs 5930463.
				 *
				 * So the raise is attached to the declaration
				 * rather than to the constant: a file no
				 * module claimed is bounded exactly as before.
				 */
				/*
				 * ASKED FOR, BY WHOEVER ASKED. `force` is set
				 * when a producer declared KOF_ENG_USE_EMU on
				 * this child and when a heuristic rule asked
				 * for the object in front of it; it is clear
				 * when nothing asked and the engine is trying
				 * the interpreter on its own guess. Reading
				 * cur_want instead covered only the first of
				 * those, so a rule that recognised a protector
				 * got the short ceiling.
				 */
				if (force)
					idle = EMU_IDLE_DECLARED;
				e = kof_emu_unp_run_pe(b.p, b.n, info, bi, bp,
						       idle,
						       sc->emu_slice != 0,
						       oep, sc->n_xw,
						       &sc->pend_decl,
						       &rep);
			}
		}
	} else {
		const struct kof_elf_info *info = kof_elf(ctx);

		if (!force && kof_emu_unp_gate(ctx, info, b.p, b.n) ==
			      KOF_EMU_UNP_NO)
			return 0;
		e = kof_emu_unp_run(b.p, b.n, info, emu_insn(b.n),
				    emu_pages(sc), &rep);
	}
	/*
	 * A SLICE THAT EXPIRED IS A PAUSE, NOT AN END - see `emu_slice`. The
	 * guest is mid-decryption and the module asked to be shown that; the
	 * machine stays alive exactly as it does for an instruction watch.
	 */
	if (e && rep.stop == KOF_EMU_STOP_BUDGET && sc->emu_slice &&
	    kof_emu_insn_count(e) < sc->emu_full)
		rep.stop = KOF_EMU_STOP_INSN;
	if (e && rep.stop == KOF_EMU_STOP_INSN) {
		/*
		 * PAUSED, NOT FINISHED. Nothing is gathered yet - the guest is
		 * mid-stub and whatever it has written so far is a snapshot of
		 * a decryptor at work. The module reads the machine, decides,
		 * and resumes. See `emu_resume` in kofsig.h.
		 */
		sc->emu_live = e;
		if (!sc->emu_rep_p)
			sc->emu_rep_p = calloc(1, sizeof *sc->emu_rep_p);
		if (sc->emu_rep_p)
			*sc->emu_rep_p = rep;
		sc->emu_paused = 1;
		return 0;
	}
	return oc_emu_gather(ctx, sc, e, rep);
}

/*
 * WHAT A RUN LEFT, TURNED INTO REGIONS - the half of kof_scan_emu_unpack that
 * happens AFTER the machine stops.
 *
 * Split out so that a PAUSED run can be resumed and gathered by the same code.
 * A module that named an instruction to stop on - see kof_emu_watch_insn - gets
 * control back with the machine intact, reads what it wanted, and asks for the
 * run to continue; when it finally stops for good, what it left is gathered
 * here exactly as it would have been without the pause. Two copies of this
 * would be two answers to "what did the run produce".
 */
uint32_t oc_emu_gather(const struct kof_obj_ctx *ctx,
			   struct kof_scanner *sc, struct kof_emu *e,
			   struct kof_emu_unp_report rep)
{
	kof_buf b;
	uint32_t it;
	uint64_t va, len, built_lo = ~0ull, built_hi = 0;
	const uint8_t *img_p = NULL;
	uint64_t img_n = 0, img_va = 0;
	struct emu_extra ex[EMU_EXTRA_MAX];
	uint32_t n_ex = 0;
	const uint8_t *bytes;
	int any, built = 0, is_pe;

	is_pe = ctx->format == KOF_FMT_PE;
	b = kof_src_buf(sc->cur_src);
	/*
	 * WHERE THE RUN STOPPED, ON REQUEST.
	 *
	 * kofemu.h says of the stop reasons that they "are the map of what to
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

		kof_emu_exc_counts(e, &xr, &xt, &xv);
		if (KOF_TRACING) {
			unsigned mi;

			fprintf(stderr, "[emu] module reads:");
			for (mi = 0; mi < kof_emu_win_mod_count(); mi++)
				fprintf(stderr, " %s=%llu",
					kof_emu_win_mod_name(mi),
					(unsigned long long)
						kof_emu_mod_reads(e, mi));
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
						kof_emu_get_reg(e, ri));
			fprintf(stderr, "\n");
		}
		{
			uint64_t hi2 = 0, hr = 0;

			kof_emu_first_hop(e, &hi2, &hr);
			fprintf(stderr, "[emu] first hop at insn=%llu rip=%#llx\n",
				(unsigned long long)hi2,
				(unsigned long long)hr);
		}
		nt = kof_emu_trace(e, tr, 256u);
		fprintf(stderr, "[emu] last rips:");
		for (ti = 0; ti < nt; ti++)
			fprintf(stderr, " %#llx", (unsigned long long)tr[ti]);
		fprintf(stderr, "\n");
		fprintf(stderr, "[emu] exc raised=%u taken=%u veh=%u "
			"null-calls=%u unhandled=%u\n", xr, xt, xv,
			kof_emu_null_calls(e), kof_emu_unhandled(e));
		fprintf(stderr, "[emu] null-reads=%u idle-max=%llu decrypt=%d\n",
			kof_emu_null_reads(e),
			(unsigned long long)kof_emu_idle_max(e),
			kof_emu_write_seen(e));
	}
	/* A diagnostic: a build choice, like the block above - see CLAUDE.md 1. */
	if (KOF_TRACING && e && kof_emu_itrace_count(e)) {
		static const char *const rn[16] = {
			"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
			"r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
		};
		unsigned have = kof_emu_itrace_count(e), k, g;

		for (k = 0; k < have; k++) {
			uint64_t at = 0;
			const char *tx = NULL;
			const uint64_t *gp = NULL;

			if (!kof_emu_itrace_get(e, k, &at, &tx, &gp))
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
			(int)rep.why, (int)rep.stop,
			(unsigned long long)rep.insn,
			(unsigned long long)rep.entry, rep.images, rep.written,
			rep.returned, rep.improvised,
			rep.detail ? rep.detail : "-",
			rep.refused ? rep.refused : "-");
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
	 * belong. See kof_pe_image_from_run: a region that starts exactly at a
	 * section's address is that section, and the allocations, the thread
	 * block, the stack and the host's own scratch are not. Assembled into
	 * one file with the parent's header, so what comes out identifies as a
	 * PE and gets regions, imports and every rule scoped to them.
	 *
	 * Before the loop below and not instead of it: a run that put nothing
	 * at a section address falls through to the old behaviour unchanged.
	 */
	if (is_pe) {
		uint8_t *whole = NULL;
		uint64_t wlen = 0;
		const struct kof_pe_info *pi = kof_pe(ctx);

		int ok = pi && pi->valid &&
			 kof_pe_image_from_run(e, pi, pi->image_base,
					       sc->obj_cap, &whole, &wlen);

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
				     si < KOF_PE_MAX_SECTIONS; si++) {
				const struct kof_pe_sec *ps = &pi->sec[si];
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
				free(sc->emu_own);
				sc->emu_own = whole;
				img_p = whole;
				img_n = wlen;
				img_va = pi->image_base;
				whole = NULL;
				built = 1;
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
				built_lo = pi->image_base;
				built_hi = pi->image_base + img_n;
			}
			free(whole);
		}
	}
	for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		uint8_t *file = NULL;
		uint64_t flen = 0;

		if (is_pe) {
			/*
			 * THE PE HALF REBUILDS FROM THE REGION, not through a
			 * reader, and the difference is not a shortcut.
			 *
			 * kof_elf_rebuild walks a guest's segments by
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
			img_p = bytes;
			img_n = len;
			img_va = va;
			built = 1;
			built_lo = va;
			built_hi = va + len;
			break;
		} else {
			if (len < 4 || memcmp(bytes, "\177ELF", 4))
				continue;
			if (!kof_elf_rebuild(va, emu_rd, e, sc->obj_cap,
					     &file, &flen, &built_lo,
					     &built_hi))
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
			free(sc->emu_own);
			sc->emu_own = file;
			img_p = file;
			img_n = flen;
			img_va = va;
			file = NULL;
			built = 1;
		}
		free(file);
		break;                  /* one program per run is what a stub
					 * produces; a second header found in
					 * its data is not a second program */
	}

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
	for (any = built, it = 0;
	     kof_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		if (va >= built_lo && va < built_hi)
			continue;               /* already in the rebuilt file */
		if (!emu_novel(ctx, bytes, len))
			continue;               /* the stub's own copy of itself */
		any = 1;
		/* Memory the run made executable, or wrote and then ran - see
		 * the write-then-execute snapshot in kofemu. Collected rather
		 * than handed over: it belongs to the same program as the
		 * image, and emu_one_child puts them together. */
		if (n_ex < EMU_EXTRA_MAX && !emu_dup(ex, n_ex, va, bytes, len)) {
			ex[n_ex].p = bytes;
			ex[n_ex].own = NULL;   /* a snapshot lives in the
						* machine, which outlives the
						* module - see emu_rgn */
			ex[n_ex].n = len;
			ex[n_ex].va = va;
			ex[n_ex].code = 1;
			n_ex++;
		} else if (n_ex >= EMU_EXTRA_MAX &&
			   !emu_dup(ex, n_ex, va, bytes, len)) {
			/* A bound on what one run may hand over. It stays a bound,
			 * and it SAYS it was reached: dropped without a word, a
			 * region past the thirty-second was evidence that simply
			 * was not there. */
			oc_scan_capped(sc, KOF_BROKEN_LIMIT);
		}
	}
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
	if (!any && (rep.stop == KOF_EMU_STOP_EXIT ||
		     rep.stop == KOF_EMU_STOP_HANDOFF ||
		     rep.stop == KOF_EMU_STOP_STALLED ||
		     rep.stop == KOF_EMU_STOP_BUDGET ||
		     rep.returned))
		for (it = 0; kof_emu_next_written(e, &it, &va, &bytes, &len); ) {
			if (va >= built_lo && va < built_hi)
				continue;
			/* What the stub pushed is not what it unpacked. See
			 * kof_emu_unp_report.stack_lo. */
			if (rep.stack_hi && va >= rep.stack_lo &&
			    va < rep.stack_hi)
				continue;
			/* Nor the exception records, which the HOST wrote. */
			if (rep.exc_hi && va >= rep.exc_lo && va < rep.exc_hi)
				continue;
			if (!emu_novel(ctx, bytes, len))
				continue;
			if (n_ex < EMU_EXTRA_MAX &&
			    !emu_dup(ex, n_ex, va, bytes, len)) {
				/*
				 * COPIED, BECAUSE THIS ONE IS BORROWED. See
				 * kof_emu_next_written: the buffer it answers
				 * with is replaced on the next call, so every
				 * region but the last would be freed before
				 * the module that asked for them ran.
				 */
				uint8_t *own = malloc((size_t)len);

				if (!own)
					break;
				memcpy(own, bytes, (size_t)len);
				ex[n_ex].p = own;
				ex[n_ex].own = own;
				ex[n_ex].n = len;
				ex[n_ex].va = va;
				ex[n_ex].code = 0;
				n_ex++;
			} else if (n_ex >= EMU_EXTRA_MAX &&
				   !emu_dup(ex, n_ex, va, bytes, len)) {
				oc_scan_capped(sc, KOF_BROKEN_LIMIT);     /* said, not dropped */
			}
		}

	/*
	 * AND THAT IS ALL A RUN DOES: it says what it found.
	 *
	 * No child is made here and none ever should be. The interpreter is
	 * the one component that executes hostile bytes, and giving it the
	 * power to create objects as well made the widest surface in the engine
	 * wider still. It gathers; a module reads the gathering and decides
	 * what any of it is; the engine builds what the module declares. See
	 * kof_scan_emu_region and kof_scan_emu_take.
	 *
	 * The regions point into the machine's own memory, so the machine stays
	 * alive until the module that asked for the run has returned - see
	 * kof_scan_emu_release.
	 */
	sc->n_emu_rgn = 0;
	if (img_p && sc->n_emu_rgn < KOF_EMU_RGN_MAX) {
		sc->emu_rgn[sc->n_emu_rgn].p = img_p;
		/* img_p is sc->emu_own, freed with it. */
		sc->emu_rgn[sc->n_emu_rgn].own = NULL;
		sc->emu_rgn[sc->n_emu_rgn].va = img_va;
		sc->emu_rgn[sc->n_emu_rgn].n = img_n;
		sc->emu_rgn[sc->n_emu_rgn].kind = KOF_EMU_RGN_IMAGE;
		sc->n_emu_rgn++;
	}
	{
		uint32_t q;

		for (q = 0; q < n_ex && sc->n_emu_rgn < KOF_EMU_RGN_MAX; q++) {
			sc->emu_rgn[sc->n_emu_rgn].p = ex[q].p;
			sc->emu_rgn[sc->n_emu_rgn].own = ex[q].own;
			sc->emu_rgn[sc->n_emu_rgn].va = ex[q].va;
			sc->emu_rgn[sc->n_emu_rgn].n = ex[q].n;
			sc->emu_rgn[sc->n_emu_rgn].kind = ex[q].code
				? KOF_EMU_RGN_EXEC : KOF_EMU_RGN_WRITTEN;
			sc->n_emu_rgn++;
		}
	}
	if (KOF_TRACING) {
		uint32_t q;

		for (q = 0; q < sc->n_emu_rgn; q++)
			fprintf(stderr,
				"[emu] rgn %u va=0x%llx len=%llu kind=%u\n", q,
				(unsigned long long)sc->emu_rgn[q].va,
				(unsigned long long)sc->emu_rgn[q].n,
				sc->emu_rgn[q].kind);
	}

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
	sc->emu_live = e;
	sc->emu_paused = 0;
	return sc->n_emu_rgn;
}

/*
 * The machine, and the regions that point into it, let go.
 *
 * Called when the module that asked for a run returns - see unpack_object.
 * Nothing a module kept a pointer to survives this, which is the point: a
 * region is valid for exactly as long as the call that asked for it.
 */
void kof_scan_emu_release(struct kof_scanner *sc)
{
	if (!sc)
		return;
	if (sc->emu_live) {
		kof_emu_free(sc->emu_live);
		sc->emu_live = NULL;
	}
	free(sc->emu_own);
	sc->emu_own = NULL;
	{
		uint32_t i;

		for (i = 0; i < sc->n_emu_rgn; i++) {
			free(sc->emu_rgn[i].own);
			sc->emu_rgn[i].own = NULL;
			sc->emu_rgn[i].p = NULL;
		}
	}
	sc->n_emu_rgn = 0;
}

/*
 * ---- WHAT A MODULE SEES OF A RUN ------------------------------------------
 *
 * The interpreter gathers and these hand the gathering over. Nothing here
 * creates an object: that is the unpack module's job, through the same
 * declarations every other producer uses.
 */
uint32_t oc_emu_run(const struct kof_obj_ctx *ctx, uint32_t vouch)
{
	/* A vouch is honoured from the --heur level the module named, and a
	 * scan with heuristics off honours none - see vouch_level. */
	int vouched;

	struct kof_scanner *sc = kof_scan_of(ctx);

	/*
	 * THE HOST'S REFUSALS, IN ONE PLACE.
	 *
	 * A module asks; whether it may is the host's answer, because every
	 * one of these is a budget - how deep through packers, how many runs
	 * this scan has already spent, whether an interpreter is allowed at
	 * all. See QUALITY_AUDIT.txt I.A.
	 */
	/*
	 * WHY A RUN DID NOT HAPPEN, on request.
	 *
	 * Every refusal below is silent and there are six of them, so a module
	 * that asked and got nothing back could not tell "the interpreter ran
	 * and the program wrote nothing" from "the host never started it" -
	 * which are opposite problems. Same argument, and same switch, as the
	 * stop-reason trace further down.
	 */
	vouched = sc && vouch && sc->heur_lvl >= vouch;
	if (sc)
		KOF_TRACE("[emu] ask: vouched=%d live=%d stance=%d packed=%d spent=%llu\n",
			vouched, sc->emu_live ? 1 : 0, (int)sc->emu_stance,
			sc->packed_here, (unsigned long long)sc->st.heur_emu);
	if (!sc || sc->emu_live)
		return 0;               /* one run at a time */
	/*
	 * AND ONE PER OBJECT. The machine is released the moment the module
	 * that drove it returns, so emu_live is clear again by the time the
	 * next module is offered the same object - and without this every
	 * module that declines it in turn would pay for a run of its own.
	 */
	if (sc->emu_ran)
		return 0;
	/* --emu never, and the packer-depth ceiling. Neither is a budget and
	 * neither yields to a vouch - see emu_stance in scan.h. */
	if (sc->emu_stance == KOF_EMU_STANCE_BANNED)
		return 0;
	/* A packer already opened this, so the payload is in hand and running
	 * it as well is peeling it and then running it anyway. Under
	 * KOF_EMU_ONLY the interpreter stands in for the packer modules, so
	 * that is not a refusal. */
	if (sc->packed_here && !kof_emu_stance_only(sc->emu_stance))
		return 0;
	/*
	 * NOBODY SPOKE FOR IT AND UNASKED RUNS ARE OFF. A module that vouches
	 * and a database that asked both get past this; what does not is the
	 * generic receiver guessing, in a mode whose caller wants no
	 * interpreter unless something argued for one.
	 */
	if (!vouched && sc->emu_stance == KOF_EMU_STANCE_NOBODY)
		return 0;
	/* The scan's own ceiling on how many runs it will spend - see
	 * KOF_SCAN_EMU_MAX. */
	if (sc->st.heur_emu >= KOF_SCAN_EMU_MAX)
		return 0;
	sc->st.heur_emu++;
	sc->emu_ran = 1;
	sc->emu_run_by = sc->cur_mod;   /* the one carrier: see kid_push */
	/*
	 * VOUCHED BY THE MODULE, OR SPOKEN FOR BY THE DATABASE.
	 *
	 * A family module vouches because it recognised its packer. The generic
	 * receiver cannot, and what speaks for its object is a rule that
	 * declared KOF_ENG_USE_EMU or a producer that said its output needs
	 * running - both resolved in unpack_object, both invisible from a
	 * module. Either way `force` means the same thing to the run: skip the
	 * entropy gate, which is an estimate about objects nobody spoke for.
	 */
	return kof_scan_emu_unpack(ctx, vouched || kof_emu_stance_asked(sc->emu_stance));
}

int oc_emu_region(const struct kof_obj_ctx *ctx, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind)
{
	return kof_scan_emu_region(kof_scan_of(ctx), i, va, len, kind);
}

/*
 * The bytes of a gathered region, which are a SNAPSHOT - see
 * `emu_region_read` in kofsig.h for why that is not the same as emu_read.
 */
uint32_t oc_emu_region_read(const struct kof_obj_ctx *ctx, uint32_t i,
				  uint64_t off, uint8_t *out, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_emu_rgn *r;

	if (!sc || !out || !n || i >= sc->n_emu_rgn)
		return 0;
	r = &sc->emu_rgn[i];
	if (!r->p || off >= r->n)
		return 0;
	if ((uint64_t)n > r->n - off)
		n = (uint32_t)(r->n - off);
	memcpy(out, r->p + off, n);
	return n;
}

/*
 * ---- CHANGING A PAUSED MACHINE ------------------------------------------
 *
 * See `emu_set_reg` in kofsig.h for why a module needs this. All three refuse
 * unless the run is PAUSED: a running machine belongs to the interpreter and a
 * finished one has already gone to the gather.
 */
void oc_emu_set_reg(const struct kof_obj_ctx *ctx, uint32_t gpr,
			  uint64_t value)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu_paused || !sc->emu_live)
		return;
	if (gpr == KUNP_REG_IP)
		kof_emu_set_rip(sc->emu_live, value);
	else
		kof_emu_set_reg(sc->emu_live, gpr, value);
}

void oc_emu_set_ip(const struct kof_obj_ctx *ctx, uint64_t va)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc && sc->emu_paused && sc->emu_live)
		kof_emu_set_rip(sc->emu_live, va);
}

uint32_t oc_emu_write(const struct kof_obj_ctx *ctx, uint64_t va,
			    const uint8_t *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu_paused || !sc->emu_live || !bytes || !n)
		return 0;
	/* All or nothing, like every other span this engine hands a module: a
	 * half-written patch is a machine nobody can reason about. */
	return kof_emu_write(sc->emu_live, va, bytes, n) ? n : 0u;
}

/* One region into the child being built, at the cursor. */
int oc_emu_take(const struct kof_obj_ctx *ctx, uint32_t i)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || i >= sc->n_emu_rgn)
		return 0;
	return oc_emit_exact(ctx, sc->emu_rgn[i].p, sc->emu_rgn[i].n);
}

/* Whether anything has already opened this object. */
int oc_opened_already(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	return sc && (sc->n_kids || sc->packed_here);
}

/* What one run left, for the module that asked for it. */
uint32_t kof_scan_emu_count(const struct kof_scanner *sc)
{
	return sc ? sc->n_emu_rgn : 0;
}

int kof_scan_emu_region(const struct kof_scanner *sc, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind)
{
	if (!sc || i >= sc->n_emu_rgn)
		return 0;
	if (va)
		*va = sc->emu_rgn[i].va;
	if (len)
		*len = sc->emu_rgn[i].n;
	if (kind)
		*kind = sc->emu_rgn[i].kind;
	return 1;
}


/*
 * A child that is already a contiguous range of this object.
 *
 * No copy and no budget: nothing was produced, the parent's mapping is simply seen
 * through a different offset. What bounds it is the child count and the depth,
 * because a window can still be a way of pointing an object at itself.
 */
void oc_emu_watch(const struct kof_obj_ctx *ctx, uint64_t rva,
			uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !len || sc->pend_n_xw >= KOF_EMU_EXEC_WATCH)
		return;
	sc->pend_xw[sc->pend_n_xw].rva = rva;
	sc->pend_xw[sc->pend_n_xw].len = len;
	sc->pend_n_xw++;
}

/* This object is a wrapper - see `supersede` in kofsig.h. */
/*
 * A register, and guest memory, of the machine the last run left.
 *
 * Both answer nothing when no machine is alive, which is the honest answer for
 * a module that never asked for a run or whose run the host refused.
 */
uint64_t oc_emu_reg(const struct kof_obj_ctx *ctx, uint32_t gpr)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu_live)
		return 0;
	if (gpr == KUNP_REG_IP)
		return kof_emu_get_rip(sc->emu_live);
	return kof_emu_get_reg(sc->emu_live, gpr);
}

uint32_t oc_emu_read(const struct kof_obj_ctx *ctx, uint64_t va,
			   uint8_t *out, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu_live || !out || !n)
		return 0;
	/* The interpreter answers all-or-nothing for a span, which is the
	 * right shape here too: a partial read of a structure is a structure
	 * nobody can check. */
	return kof_emu_read(sc->emu_live, va, out, n) ? n : 0u;
}


/*
 * The instructions a module wants the run paused on, and carrying on from a
 * pause - see `emu_watch_insn` in kofsig.h.
 */
void oc_emu_watch_insn(const struct kof_obj_ctx *ctx,
			     const uint8_t *bytes, uint32_t n, uint32_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	/* No bytes disarms - see kof_emu_watch_insn. Applied to a LIVE machine
	 * too, because that is when a module gives up on pausing and wants the
	 * run to finish. */
	if (!bytes || !n) {
		sc->pend_decl.n_iw = 0;
		sc->pend_decl.iw_len = 0;
		if (sc->emu_live)
			kof_emu_watch_insn(sc->emu_live, NULL, 0);
		return;
	}
	if (n > sizeof sc->pend_decl.iw[0].b ||
	    sc->pend_decl.n_iw >= KOF_EMU_INSN_WATCH)
		return;
	memcpy(sc->pend_decl.iw[sc->pend_decl.n_iw].b, bytes, n);
	sc->pend_decl.iw[sc->pend_decl.n_iw].n = (uint8_t)n;
	sc->pend_decl.n_iw++;
	sc->pend_decl.iw_len = len;
}

/*
 * WHAT THE MACHINE IS TOLD BEFORE IT STARTS - see `emu_api_returns` and
 * `emu_patch` in kofsig.h. Both only record: the run has not been built yet,
 * and the declaration travels to it in sc->pend_decl. Both answer 0 when the
 * declaration was not kept (full, or malformed) so a module can tell.
 */
uint32_t oc_emu_api_returns(const struct kof_obj_ctx *ctx, const char *name,
			    uint64_t ret)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_emu_decl *d;
	size_t l;

	if (!sc || !name)
		return 0;
	d = &sc->pend_decl;
	l = strlen(name);
	if (!l || l >= KOF_EMU_SHIM_NAME)
		return 0;
	{
		uint32_t k;

		for (k = 0; k < d->n_shim; k++)
			if (!strcmp(d->shim[k].name, name)) {
				d->shim[k].ret = ret;
				return 1;
			}
	}
	if (d->n_shim >= KOF_EMU_SHIM_MAX)
		return 0;
	memcpy(d->shim[d->n_shim].name, name, l + 1u);
	d->shim[d->n_shim].ret = ret;
	d->n_shim++;
	return 1;
}

uint32_t oc_emu_patch(const struct kof_obj_ctx *ctx, const uint8_t *find,
		      const uint8_t *rep, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_emu_decl *d;

	if (!sc || !find || !rep || !n || n > KOF_EMU_PATCH_LEN)
		return 0;
	d = &sc->pend_decl;
	if (d->n_patch >= KOF_EMU_PATCH_MAX)
		return 0;
	memcpy(d->patch[d->n_patch].find, find, n);
	memcpy(d->patch[d->n_patch].rep, rep, n);
	d->patch[d->n_patch].n = (uint8_t)n;
	d->n_patch++;
	return 1;
}

/*
 * End a paused run where it stands and gather what it left - see `emu_stop`
 * in kofsig.h for the measurement that made this necessary.
 *
 * THE SAME HAND-OVER AS A FINISHED RUN. oc_emu_gather takes ownership of the
 * machine, so emu_live is cleared here exactly as oc_emu_resume clears it; a
 * module that stops is not holding anything afterwards that one which ran to
 * the end would not be.
 */



/*
 * How far a run may go before handing control back - see `emu_slice`.
 * Recorded and not acted on here: the run itself reads it, because the
 * ceiling has to be in place before the machine starts.
 */
void oc_emu_slice(const struct kof_obj_ctx *ctx, uint64_t insn)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc)
		sc->emu_slice = insn;
}

uint32_t oc_emu_stop(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_emu *e;

	if (!sc || !sc->emu_paused || !sc->emu_live || !sc->emu_rep_p)
		return 0;
	e = sc->emu_live;
	sc->emu_rep_p->insn = kof_emu_insn_count(e);
	sc->emu_paused = 0;
	sc->emu_live = NULL;
	return oc_emu_gather(ctx, sc, e, *sc->emu_rep_p);
}

uint32_t oc_emu_resume(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kof_emu *e;
	enum kof_emu_stop st;

	if (!sc || !sc->emu_paused || !sc->emu_live || !sc->emu_rep_p)
		return 0;
	e = sc->emu_live;
	/*
	 * Another slice, if the module asked for slices - see `emu_slice`.
	 *
	 * AND THE WRITTEN PAGES ARE SNAPSHOTTED FIRST, which is not optional.
	 * emu_unpack.c's own extension loop does exactly this between slices,
	 * with the reason beside it: what a slice earned is kept before the
	 * next one is risked. Resuming without it threw away everything the
	 * previous slices had decrypted - measured, detection fell from three
	 * samples of four to one.
	 */
	if (sc->emu_slice) {
		uint64_t at = kof_emu_insn_count(e);
		uint64_t to = at + sc->emu_slice;

		kof_emu_snap_written(e);
		kof_emu_set_max_insn(e, to < sc->emu_full ? to : sc->emu_full);
	}
	KOF_TIME_BEGIN(KOF_T_EMU);
	st = kof_emu_run(e);
	KOF_TIME_END(KOF_T_EMU);
	if (st == KOF_EMU_STOP_BUDGET && sc->emu_slice &&
	    kof_emu_insn_count(e) < sc->emu_full)
		st = KOF_EMU_STOP_INSN;
	sc->emu_rep_p->stop = st;
	sc->emu_rep_p->insn = kof_emu_insn_count(e);
	if (st == KOF_EMU_STOP_INSN)
		return 0;               /* paused again */
	/*
	 * Finished. The machine goes to the gather, which takes ownership of it
	 * exactly as it does on the path with no pause - so emu_live is cleared
	 * here and set again there.
	 */
	sc->emu_paused = 0;
	sc->emu_live = NULL;
	return oc_emu_gather(ctx, sc, e, *sc->emu_rep_p);
}

