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

#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "objctx_int.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <genotype/image/elf_rebuild.h>

/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_forms below. */
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */


#include "../analyzers/genome_obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int kof_scan_emu_region(const struct kof_scanner *sc, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind);

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
	return room / KGENOME_EMU_PAGE;
}

/*
 * THE INTERPRETER'S BUDGET, as kgenome takes it: the engine's two numbers above
 * (the instruction budget `insn`, which the caller may have cut to a slice, and
 * the address space emu_pages gives it) carried in the struct kgenome_budget the
 * lib reads and nothing else - the lib never goes looking for them in engine
 * state. The values are unchanged; this is only where they are written down.
 */
static struct kgenome_budget emu_budget(const struct kof_scanner *sc,
					uint64_t obj_size, uint64_t insn)
{
	struct kgenome_budget kb;

	kgenome_budget_default(&kb, obj_size, 0);
	kb.max_insn = insn;
	kb.max_bytes = emu_pages(sc) * KGENOME_EMU_PAGE;
	return kb;
}


int oc_emit_exact(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n)
{
	return oc_emit_all(ctx, p, n) == n;
}


uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu_unp_report rep;
	struct kgenome_emu *e;
	kof_buf b;
	int is_pe;

	if (!sc || !sc->cur.src || !ctx->file_header)
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
	b = kof_src_buf(sc->cur.src);
	if (is_pe) {
		const struct kgenome_pe_info *info = kof_pe(ctx);

		struct kgenome_obj gobj;

		kof_genome_obj(ctx, &gobj);
		if (!force && kgenome_emu_unp_gate_pe(&gobj, info, b.p, b.n) ==
			      KGENOME_EMU_UNP_NO)
			return 0;
		{
			struct kgenome_emu_oep oep[KGENOME_EMU_EXEC_WATCH];
			unsigned k;

			for (k = 0; k < sc->cur.n_xw; k++) {
				oep[k].rva = sc->cur.xw[k].rva;
				oep[k].len = sc->cur.xw[k].len;
			}
			KOF_TRACE("[emu] oep ranges=%u\n", sc->cur.n_xw);
			{
				/* See emu_nolimit_ms in emu_unpack_*.c: the
				 * experiment switch, which replaces every work
				 * bound with a wall clock. 2 GB of guest pages
				 * is what "bounded by RAM" means here. */
				uint64_t bi = emu_insn(b.n);
				uint64_t idle = 0;
				struct kgenome_budget kb;

				/*
				 * AND A SLICE, WHEN THE MODULE ASKED FOR ONE -
				 * see `emu_slice`. The real ceiling is kept so
				 * that a stop at the slice can be told from a
				 * stop at the budget, which are opposite
				 * answers: one means "look and carry on", the
				 * other means "this is all there will be".
				 */
				sc->obj.emu.full = bi;
				if (sc->obj.emu.slice && sc->obj.emu.slice < bi)
					bi = sc->obj.emu.slice;
				KOF_TRACE("[emu] budget full=%llu slice=%llu use=%llu\n",
						(unsigned long long)sc->obj.emu.full,
						(unsigned long long)sc->obj.emu.slice,
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
				kb = emu_budget(sc, b.n, bi);
				e = kgenome_emu_unp_run_pe(&(const struct kgenome_emu_unp_pe_req){
						.file = b.p,
						.n = b.n,
						.info = info,
						.imports = oc_pe_imports(sc, ctx),
						.bud = &kb,
						.idle = idle,
						.hand_back = sc->obj.emu.slice != 0,
						.extensions = force ? KGENOME_EMU_EXTEND_MAX : 0u,
						.oep = oep,
						.n_oep = sc->cur.n_xw,
						.decl = &sc->pend.decl,
						.rep = &rep,
					});
			}
		}
	} else {
		const struct kgenome_elf_info *info = kof_elf(ctx);

		struct kgenome_obj gobj;

		kof_genome_obj(ctx, &gobj);
		if (!force && kgenome_emu_unp_gate(&gobj, info, b.p, b.n) ==
			      KGENOME_EMU_UNP_NO)
			return 0;
		{
			struct kgenome_budget kb = emu_budget(sc, b.n, emu_insn(b.n));

			e = kgenome_emu_unp_run(b.p, b.n, info, &kb, &rep);
		}
	}
	/*
	 * A SLICE THAT EXPIRED IS A PAUSE, NOT AN END - see `emu_slice`. The
	 * guest is mid-decryption and the module asked to be shown that; the
	 * machine stays alive exactly as it does for an instruction watch.
	 */
	if (e && rep.stop == KGENOME_EMU_STOP_BUDGET && sc->obj.emu.slice &&
	    kgenome_emu_insn_count(e) < sc->obj.emu.full)
		rep.stop = KGENOME_EMU_STOP_INSN;
	if (e && rep.stop == KGENOME_EMU_STOP_INSN) {
		/*
		 * PAUSED, NOT FINISHED. Nothing is gathered yet - the guest is
		 * mid-stub and whatever it has written so far is a snapshot of
		 * a decryptor at work. The module reads the machine, decides,
		 * and resumes. See `emu_resume` in kofsig.h.
		 */
		sc->emu.live = e;
		if (!sc->emu.rep_p)
			sc->emu.rep_p = calloc(1, sizeof *sc->emu.rep_p);
		if (sc->emu.rep_p)
			*sc->emu.rep_p = rep;
		sc->emu.paused = 1;
		return 0;
	}
	return oc_emu_gather(ctx, sc, e, rep);
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
	if (sc->emu.live) {
		kgenome_emu_free(sc->emu.live);
		sc->emu.live = NULL;
	}
	free(sc->emu.own);
	sc->emu.own = NULL;
	{
		uint32_t i;

		for (i = 0; i < sc->emu.n_rgn; i++) {
			free(sc->emu.rgn[i].own);
			sc->emu.rgn[i].own = NULL;
			sc->emu.rgn[i].p = NULL;
		}
	}
	sc->emu.n_rgn = 0;
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
	vouched = sc && vouch && sc->cur.heur_lvl >= vouch;
	if (sc)
		KOF_TRACE("[emu] ask: vouched=%d live=%d stance=%d packed=%d spent=%llu\n",
			vouched, sc->emu.live ? 1 : 0, (int)sc->obj.emu.stance,
			sc->obj.open.packed_here, (unsigned long long)sc->st.heur_emu);
	if (!sc || sc->emu.live)
		return 0;               /* one run at a time */
	/*
	 * AND ONE PER OBJECT. The machine is released the moment the module
	 * that drove it returns, so emu_live is clear again by the time the
	 * next module is offered the same object - and without this every
	 * module that declines it in turn would pay for a run of its own.
	 */
	if (sc->obj.emu.ran)
		return 0;
	/* --emu never, and the packer-depth ceiling. Neither is a budget and
	 * neither yields to a vouch - see emu_stance in scan.h. */
	if (sc->obj.emu.stance == KOF_EMU_STANCE_BANNED)
		return 0;
	/* A packer already opened this, so the payload is in hand and running
	 * it as well is peeling it and then running it anyway. Under
	 * KOF_EMU_ONLY the interpreter stands in for the packer modules, so
	 * that is not a refusal. */
	if (sc->obj.open.packed_here && !kof_emu_stance_only(sc->obj.emu.stance))
		return 0;
	/*
	 * NOBODY SPOKE FOR IT AND UNASKED RUNS ARE OFF. A module that vouches
	 * and a database that asked both get past this; what does not is the
	 * generic receiver guessing, in a mode whose caller wants no
	 * interpreter unless something argued for one.
	 */
	if (!vouched && sc->obj.emu.stance == KOF_EMU_STANCE_NOBODY)
		return 0;
	/* The scan's own ceiling on how many runs it will spend - see
	 * KOF_SCAN_EMU_MAX. */
	if (sc->st.heur_emu >= KOF_SCAN_EMU_MAX)
		return 0;
	sc->st.heur_emu++;
	sc->obj.emu.ran = 1;
	sc->obj.emu.run_by = sc->mod.cur;   /* the one carrier: see kid_push */
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
	return kof_scan_emu_unpack(ctx, vouched || kof_emu_stance_asked(sc->obj.emu.stance));
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

	if (!sc || !out || !n || i >= sc->emu.n_rgn)
		return 0;
	r = &sc->emu.rgn[i];
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

	if (!sc || !sc->emu.paused || !sc->emu.live)
		return;
	if (gpr == KUNP_REG_IP)
		kgenome_emu_set_rip(sc->emu.live, value);
	else
		kgenome_emu_set_reg(sc->emu.live, gpr, value);
}

void oc_emu_set_ip(const struct kof_obj_ctx *ctx, uint64_t va)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc && sc->emu.paused && sc->emu.live)
		kgenome_emu_set_rip(sc->emu.live, va);
}

uint32_t oc_emu_write(const struct kof_obj_ctx *ctx, uint64_t va,
			    const uint8_t *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu.paused || !sc->emu.live || !bytes || !n)
		return 0;
	/* All or nothing, like every other span this engine hands a module: a
	 * half-written patch is a machine nobody can reason about. */
	return kgenome_emu_write(sc->emu.live, va, bytes, n) ? n : 0u;
}

/* One region into the child being built, at the cursor. */
int oc_emu_take(const struct kof_obj_ctx *ctx, uint32_t i)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || i >= sc->emu.n_rgn)
		return 0;
	return oc_emit_exact(ctx, sc->emu.rgn[i].p, sc->emu.rgn[i].n);
}

/* Whether anything has already opened this object. */
int oc_opened_already(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	return sc && (sc->child.n || sc->obj.open.packed_here);
}

static int kof_scan_emu_region(const struct kof_scanner *sc, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind)
{
	if (!sc || i >= sc->emu.n_rgn)
		return 0;
	if (va)
		*va = sc->emu.rgn[i].va;
	if (len)
		*len = sc->emu.rgn[i].n;
	if (kind)
		*kind = sc->emu.rgn[i].kind;
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

	if (!sc || !len || sc->pend.n_xw >= KGENOME_EMU_EXEC_WATCH)
		return;
	sc->pend.xw[sc->pend.n_xw].rva = rva;
	sc->pend.xw[sc->pend.n_xw].len = len;
	sc->pend.n_xw++;
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

	if (!sc || !sc->emu.live)
		return 0;
	if (gpr == KUNP_REG_IP)
		return kgenome_emu_get_rip(sc->emu.live);
	return kgenome_emu_get_reg(sc->emu.live, gpr);
}

uint32_t oc_emu_read(const struct kof_obj_ctx *ctx, uint64_t va,
			   uint8_t *out, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu.live || !out || !n)
		return 0;
	/* The interpreter answers all-or-nothing for a span, which is the
	 * right shape here too: a partial read of a structure is a structure
	 * nobody can check. */
	return kgenome_emu_read(sc->emu.live, va, out, n) ? n : 0u;
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
	/* No bytes disarms - see kgenome_emu_watch_insn. Applied to a LIVE machine
	 * too, because that is when a module gives up on pausing and wants the
	 * run to finish. */
	if (!bytes || !n) {
		sc->pend.decl.n_iw = 0;
		sc->pend.decl.iw_len = 0;
		if (sc->emu.live)
			kgenome_emu_watch_insn(sc->emu.live, NULL, 0);
		return;
	}
	if (n > sizeof sc->pend.decl.iw[0].b ||
	    sc->pend.decl.n_iw >= KGENOME_EMU_INSN_WATCH)
		return;
	memcpy(sc->pend.decl.iw[sc->pend.decl.n_iw].b, bytes, n);
	sc->pend.decl.iw[sc->pend.decl.n_iw].n = (uint8_t)n;
	sc->pend.decl.n_iw++;
	sc->pend.decl.iw_len = len;
}

/*
 * WHAT THE MACHINE IS TOLD BEFORE IT STARTS - see `emu_api_returns` and
 * `emu_patch` in kofsig.h. Both only record: the run has not been built yet,
 * and the declaration travels to it in sc->pend.decl. Both answer 0 when the
 * declaration was not kept (full, or malformed) so a module can tell.
 */
uint32_t oc_emu_api_returns(const struct kof_obj_ctx *ctx, const char *name,
			    uint64_t ret)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu_decl *d;
	size_t l;

	if (!sc || !name)
		return 0;
	d = &sc->pend.decl;
	l = strlen(name);
	if (!l || l >= KGENOME_EMU_SHIM_NAME)
		return 0;
	{
		uint32_t k;

		for (k = 0; k < d->n_shim; k++)
			if (!strcmp(d->shim[k].name, name)) {
				d->shim[k].ret = ret;
				return 1;
			}
	}
	if (d->n_shim >= KGENOME_EMU_SHIM_MAX)
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
	struct kgenome_emu_decl *d;

	if (!sc || !find || !rep || !n || n > KGENOME_EMU_PATCH_LEN)
		return 0;
	d = &sc->pend.decl;
	if (d->n_patch >= KGENOME_EMU_PATCH_MAX)
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
		sc->obj.emu.slice = insn;
}

uint32_t oc_emu_stop(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu *e;

	if (!sc || !sc->emu.paused || !sc->emu.live || !sc->emu.rep_p)
		return 0;
	e = sc->emu.live;
	sc->emu.rep_p->insn = kgenome_emu_insn_count(e);
	sc->emu.paused = 0;
	sc->emu.live = NULL;
	return oc_emu_gather(ctx, sc, e, *sc->emu.rep_p);
}

uint32_t oc_emu_resume(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu *e;
	enum kgenome_emu_stop st;

	if (!sc || !sc->emu.paused || !sc->emu.live || !sc->emu.rep_p)
		return 0;
	e = sc->emu.live;
	/*
	 * Another slice, if the module asked for slices - see `emu_slice`.
	 *
	 * AND THE WRITTEN PAGES ARE SNAPSHOTTED FIRST, which is not optional.
	 * emu_unpack_pe_dump.c's own extension loop does exactly this between slices,
	 * with the reason beside it: what a slice earned is kept before the
	 * next one is risked. Resuming without it threw away everything the
	 * previous slices had decrypted - measured, detection fell from three
	 * samples of four to one.
	 */
	if (sc->obj.emu.slice) {
		uint64_t at = kgenome_emu_insn_count(e);
		uint64_t to = at + sc->obj.emu.slice;

		kgenome_emu_snap_written(e);
		kgenome_emu_set_max_insn(e, to < sc->obj.emu.full ? to : sc->obj.emu.full);
	}
	KOF_TIME_BEGIN(KOF_T_EMU);
	st = kgenome_emu_run(e);
	KOF_TIME_END(KOF_T_EMU);
	if (st == KGENOME_EMU_STOP_BUDGET && sc->obj.emu.slice &&
	    kgenome_emu_insn_count(e) < sc->obj.emu.full)
		st = KGENOME_EMU_STOP_INSN;
	sc->emu.rep_p->stop = st;
	sc->emu.rep_p->insn = kgenome_emu_insn_count(e);
	if (st == KGENOME_EMU_STOP_INSN)
		return 0;               /* paused again */
	/*
	 * Finished. The machine goes to the gather, which takes ownership of it
	 * exactly as it does on the path with no pause - so emu_live is cleared
	 * here and set again there.
	 */
	sc->emu.paused = 0;
	sc->emu.live = NULL;
	return oc_emu_gather(ctx, sc, e, *sc->emu.rep_p);
}
